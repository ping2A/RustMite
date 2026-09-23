use super::ast::{
    CompareOp, JoinType, RplCommand, RplQuery, SearchExpr, TimeAnchor, TimeRange, TimeUnit,
};
use nom::branch::alt;
use nom::bytes::complete::{tag, tag_no_case, take_while1};
use nom::character::complete::{char, multispace0, multispace1};
use nom::combinator::{opt, recognize, value};
use nom::multi::{many0, separated_list1};
use nom::sequence::{delimited, pair, preceded};
use nom::IResult;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("parse error: {0}")]
    Nom(String),
}

/// Strip stray commas immediately before `|` (Splunk-style typos: `foo, | head`).
fn normalize_commas_before_pipe(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_quote = false;
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            in_quote = !in_quote;
            out.push(c);
            i += 1;
            continue;
        }
        if !in_quote && c == ',' {
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j < chars.len() && chars[j] == '|' {
                i = j;
                if out.chars().last().is_some_and(|c| !c.is_whitespace()) {
                    out.push(' ');
                }
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Comma or whitespace between search predicates (implicit AND).
fn search_sep(input: &str) -> IResult<&str, ()> {
    alt((
        value((), preceded(tag(","), multispace0)),
        value((), multispace1),
    ))(input)
}

pub fn parse_rpl(input: &str) -> Result<RplQuery, ParseError> {
    let trimmed = normalize_commas_before_pipe(input.trim());
    let (rest, query) = rpl_query(trimmed.as_str()).map_err(|e| ParseError::Nom(format!("{e}")))?;
    if !rest.trim().is_empty() {
        return Err(ParseError::Nom(format!("trailing input: {rest}")));
    }
    Ok(query)
}

fn rpl_query(input: &str) -> IResult<&str, RplQuery> {
    let (input, _) = multispace0(input)?;
    let (input, time_range) = opt(time_modifier)(input)?;
    let (input, _) = multispace0(input)?;
    let (input, search) = search_clause(input)?;
    let (input, commands) = many0(preceded(pair(multispace0, char('|')), rpl_command))(input)?;
    Ok((
        input,
        RplQuery {
            time_range,
            search,
            commands,
        },
    ))
}

fn time_modifier(input: &str) -> IResult<&str, TimeRange> {
    let (input, _) = opt(preceded(tag("@timestamp"), multispace1))(input)?;
    alt((time_last, time_now_minus))(input)
}

fn time_amount_unit(input: &str) -> IResult<&str, (u32, TimeUnit)> {
    let (input, amount) = nom::character::complete::u32(input)?;
    let (input, unit) = alt((
        value(TimeUnit::Minutes, tag("m")),
        value(TimeUnit::Minutes, tag("min")),
        value(TimeUnit::Hours, tag("h")),
        value(TimeUnit::Hours, tag("hr")),
        value(TimeUnit::Days, tag("d")),
        value(TimeUnit::Days, tag("day")),
        value(TimeUnit::Weeks, tag("w")),
        value(TimeUnit::Weeks, tag("week")),
    ))(input)?;
    Ok((input, (amount, unit)))
}

fn time_last(input: &str) -> IResult<&str, TimeRange> {
    let (input, _) = tag_no_case("last")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, (amount, unit)) = time_amount_unit(input)?;
    Ok((
        input,
        TimeRange {
            amount,
            unit,
            anchor: TimeAnchor::Last,
        },
    ))
}

fn time_now_minus(input: &str) -> IResult<&str, TimeRange> {
    let (input, _) = tag_no_case("now-")(input)?;
    let (input, (amount, unit)) = time_amount_unit(input)?;
    Ok((
        input,
        TimeRange {
            amount,
            unit,
            anchor: TimeAnchor::NowMinus,
        },
    ))
}

fn mpl_query_in_brackets(input: &str) -> IResult<&str, RplQuery> {
    let (input, _) = multispace0(input)?;
    let (input, time_range) = opt(time_modifier)(input)?;
    let (input, _) = multispace0(input)?;
    let (input, search) = search_clause(input)?;
    let (input, commands) = many0(preceded(pair(multispace0, char('|')), rpl_command))(input)?;
    let (input, _) = preceded(multispace0, char(']'))(input)?;
    Ok((
        input,
        RplQuery {
            time_range,
            search,
            commands,
        },
    ))
}

fn rpl_command(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = multispace0(input)?;
    alt((
        cmd_where,
        cmd_search,
        cmd_stats,
        cmd_head,
        cmd_sort,
        cmd_timechart,
        cmd_eval,
        cmd_rename,
        cmd_lookup,
        cmd_dedup,
        cmd_rex,
        cmd_join,
        cmd_fields,
    ))(input)
}

fn cmd_where(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag_no_case("where")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, expr) = search_expr(input)?;
    Ok((input, RplCommand::Where(expr)))
}

/// Splunk-style alias for `where` (used by case entity drill-down links).
fn cmd_search(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag_no_case("search")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, expr) = search_expr(input)?;
    Ok((input, RplCommand::Where(expr)))
}

/// Separator between `stats ... by` fields: comma and/or whitespace (Splunk-style `a, b` or `a b`).
fn stats_by_sep(input: &str) -> IResult<&str, ()> {
    let (input, _) = multispace0(input)?;
    let (input, _) = alt((tag(","), multispace1))(input)?;
    let (input, _) = multispace0(input)?;
    Ok((input, ()))
}

/// Separator between `fields` names (`timestamp, source` or `package message`).
fn fields_sep(input: &str) -> IResult<&str, ()> {
    alt((
        value((), preceded(tag(","), multispace0)),
        value((), multispace1),
    ))(input)
}

fn cmd_stats(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("stats")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, agg) = take_while1(|c: char| c.is_alphanumeric() || c == '_')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, field, by) =
        if let Ok((input, by_fields)) = preceded(
            tag("by"),
            preceded(multispace1, separated_list1(stats_by_sep, field_name)),
        )(input)
        {
            let (input, _) = opt(preceded(multispace0, char(',')))(input)?;
            (input, None, by_fields)
        } else {
            let (input, field) = opt(field_name)(input)?;
            let (input, _) = multispace0(input)?;
            let (input, by) = opt(preceded(
                tag("by"),
                preceded(multispace1, separated_list1(stats_by_sep, field_name)),
            ))(input)?;
            let (input, _) = opt(preceded(multispace0, char(',')))(input)?;
            (input, field, by.unwrap_or_default())
        };
    Ok((
        input,
        RplCommand::Stats {
            agg: agg.to_string(),
            field: field.map(|s| s.to_string()),
            by: by.into_iter().map(|s| s.to_string()).collect(),
        },
    ))
}

fn cmd_head(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("head")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, n) = nom::character::complete::u32(input)?;
    Ok((input, RplCommand::Head { limit: n }))
}

fn cmd_sort(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("sort")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, desc) = opt(tag("-"))(input)?;
    let (input, field) = field_name(input)?;
    Ok((
        input,
        RplCommand::Sort {
            field: field.to_string(),
            desc: desc.is_some(),
        },
    ))
}

fn cmd_eval(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("eval")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, field) = field_name(input)?;
    let (input, _) = char('=')(input)?;
    let (input, expr) = eval_expr_body(input)?;
    Ok((
        input,
        RplCommand::Eval {
            field: field.to_string(),
            expr: expr.trim().to_string(),
        },
    ))
}

fn eval_expr_body(input: &str) -> IResult<&str, &str> {
    recognize(take_while1(|c: char| c != '|'))(input)
}

fn cmd_rename(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("rename")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, old) = field_name(input)?;
    let (input, _) = alt((
        delimited(multispace1, tag_no_case("AS"), multispace1),
        multispace1,
    ))(input)?;
    let (input, new) = field_name(input)?;
    Ok((
        input,
        RplCommand::Rename {
            old: old.to_string(),
            new: new.to_string(),
        },
    ))
}

fn cmd_lookup(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("lookup")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, first) = field_name(input)?;
    let (input, second) = opt(preceded(multispace1, field_name))(input)?;
    let (field, prefix) = if let Some(f) = second {
        (f.to_string(), first.to_string())
    } else {
        (first.to_string(), "lookup".into())
    };
    Ok((
        input,
        RplCommand::Lookup { field, prefix },
    ))
}

fn cmd_dedup(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("dedup")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, field) = field_name(input)?;
    Ok((
        input,
        RplCommand::Dedup {
            field: field.to_string(),
        },
    ))
}

fn cmd_rex(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("rex")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, name) = field_name(input)?;
    let (input, _) = char('=')(input)?;
    let (input, pattern) = rex_pattern(input)?;
    let (input, field) = opt(preceded(
        pair(multispace0, tag("field")),
        preceded(pair(multispace0, char('=')), field_name),
    ))(input)?;
    Ok((
        input,
        RplCommand::Rex {
            name: name.to_string(),
            pattern: pattern.to_string(),
            field: field.unwrap_or("message").to_string(),
        },
    ))
}

fn rex_pattern(input: &str) -> IResult<&str, &str> {
    alt((
        delimited(char('"'), take_while1(|c| c != '"'), char('"')),
        delimited(char('\''), take_while1(|c| c != '\''), char('\'')),
        delimited(
            char('('),
            take_while1(|c| c != ')'),
            char(')'),
        ),
    ))(input)
}

fn cmd_join(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("join")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, join_type) = opt(preceded(
        tag("type"),
        preceded(
            pair(multispace0, char('=')),
            alt((
                value(JoinType::Inner, tag("inner")),
                value(JoinType::Left, tag("left")),
            )),
        ),
    ))(input)?;
    let (input, _) = multispace0(input)?;
    let (input, field) = field_name(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('[')(input)?;
    let (input, subquery) = mpl_query_in_brackets(input)?;
    Ok((
        input,
        RplCommand::Join {
            join_type: join_type.unwrap_or(JoinType::Inner),
            field: field.to_string(),
            subquery,
        },
    ))
}

fn cmd_fields(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("fields")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, names) = separated_list1(fields_sep, field_name)(input)?;
    Ok((
        input,
        RplCommand::Fields {
            names: names.into_iter().map(|s| s.to_string()).collect(),
        },
    ))
}

fn cmd_timechart(input: &str) -> IResult<&str, RplCommand> {
    let (input, _) = tag("timechart")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, _) = tag("span=")(input)?;
    let (input, span) =
        take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == 'm' || c == 'h' || c == 'd')(input)?;
    let (input, _) = multispace1(input)?;
    let (input, (agg, field)) = timechart_agg(input)?;
    let (input, by) = opt(preceded(
        pair(multispace0, tag("by")),
        preceded(multispace1, field_name),
    ))(input)?;
    let (input, limit) = opt(preceded(
        pair(multispace0, tag("limit")),
        preceded(
            pair(multispace0, char('=')),
            nom::character::complete::u32,
        ),
    ))(input)?;
    let (input, useother) = opt(preceded(
        pair(multispace0, tag("useother")),
        preceded(
            pair(multispace0, char('=')),
            alt((
                value(false, tag("false")),
                value(true, tag("true")),
            )),
        ),
    ))(input)?;
    Ok((
        input,
        RplCommand::Timechart {
            span: span.to_string(),
            agg: agg.to_string(),
            field: field.map(|s| s.to_string()),
            by: by.map(|s| s.to_string()),
            limit,
            useother,
        },
    ))
}

/// `count` | `avg raw_level` | `avg(raw_level)` | `min`/`max`/`sum` with field.
fn timechart_agg(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let (input, agg) = alt((
        tag("avg"),
        tag("min"),
        tag("max"),
        tag("sum"),
        tag("count"),
    ))(input)?;
    // Parenthesized form: avg(raw_level)
    if let Ok((rest, field)) = delimited(char('('), field_name, char(')'))(input) {
        return Ok((rest, (agg, Some(field))));
    }
    if agg == "count" {
        return Ok((input, (agg, None)));
    }
    let (input, _) = multispace1(input)?;
    let (input, field) = field_name(input)?;
    Ok((input, (agg, Some(field))))
}

fn search_clause(input: &str) -> IResult<&str, SearchExpr> {
    let (input, _) = multispace0(input)?;
    if input.is_empty() {
        return Ok((input, SearchExpr::True));
    }
    let (input, first) = or_expr(input)?;
    let (input, rest) = many0(preceded(search_sep, or_expr))(input)?;
    if rest.is_empty() {
        Ok((input, first))
    } else {
        let mut parts = vec![first];
        parts.extend(rest);
        Ok((input, SearchExpr::And(parts)))
    }
}

fn search_expr(input: &str) -> IResult<&str, SearchExpr> {
    search_clause(input)
}

fn or_expr(input: &str) -> IResult<&str, SearchExpr> {
    let (input, first) = and_expr(input)?;
    let (input, rest) = many0(preceded(
        delimited(multispace0, tag("OR"), multispace1),
        and_expr,
    ))(input)?;
    if rest.is_empty() {
        Ok((input, first))
    } else {
        let mut v = vec![first];
        v.extend(rest);
        Ok((input, SearchExpr::Or(v)))
    }
}

fn and_expr(input: &str) -> IResult<&str, SearchExpr> {
    let (input, first) = primary_expr(input)?;
    let (input, rest) = many0(preceded(
        delimited(multispace0, tag("AND"), multispace1),
        primary_expr,
    ))(input)?;
    if rest.is_empty() {
        Ok((input, first))
    } else {
        let mut v = vec![first];
        v.extend(rest);
        Ok((input, SearchExpr::And(v)))
    }
}

fn primary_expr(input: &str) -> IResult<&str, SearchExpr> {
    alt((
        not_expr,
        delimited(
            char('('),
            search_expr,
            preceded(multispace0, char(')')),
        ),
        field_in_list,
        field_compare,
        bare_token,
    ))(input)
}

fn not_expr(input: &str) -> IResult<&str, SearchExpr> {
    let (input, _) = tag("NOT")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, inner) = primary_expr_no_not(input)?;
    Ok((input, SearchExpr::Not(Box::new(inner))))
}

fn primary_expr_no_not(input: &str) -> IResult<&str, SearchExpr> {
    alt((
        delimited(
            char('('),
            search_expr,
            preceded(multispace0, char(')')),
        ),
        field_in_list,
        field_compare,
        bare_token,
    ))(input)
}

fn field_in_list(input: &str) -> IResult<&str, SearchExpr> {
    let (input, field) = field_name(input)?;
    let (input, negate) = opt(preceded(
        multispace1,
        alt((tag("NOT"), tag("not"))),
    ))(input)?;
    let (input, _) = preceded(multispace0, tag_no_case("IN"))(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, values) = separated_list1(
        delimited(multispace0, char(','), multispace0),
        quoted_or_bare,
    )(input)?;
    let (input, _) = char(')')(input)?;
    Ok((
        input,
        SearchExpr::In {
            field: field.to_string(),
            values: values.into_iter().map(|s| s.to_string()).collect(),
            negate: negate.is_some(),
        },
    ))
}

fn field_compare(input: &str) -> IResult<&str, SearchExpr> {
    let (input, bang_negate) = opt(char('!'))(input)?;
    let (input, field) = field_name(input)?;
    let (input, op) = alt((
        value(CompareOp::Ne, tag("!=")),
        value(CompareOp::Gte, tag(">=")),
        value(CompareOp::Lte, tag("<=")),
        value(CompareOp::Eq, char('=')),
        value(CompareOp::Gt, char('>')),
        value(CompareOp::Lt, char('<')),
    ))(input)?;
    let (input, value) = quoted_or_bare(input)?;
    let op = if bang_negate.is_some() {
        CompareOp::Ne
    } else {
        op
    };
    Ok((
        input,
        SearchExpr::Field {
            field: field.to_string(),
            op,
            value: value.to_string(),
        },
    ))
}

fn bare_token(input: &str) -> IResult<&str, SearchExpr> {
    let (input, tok) = recognize(take_while1(|c: char| {
        c != '!' && !c.is_whitespace() && c != '|' && c != '=' && c != '(' && c != ')'
    }))(input)?;
    if tok.contains('*') || tok.contains('?') {
        Ok((
            input,
            SearchExpr::Wildcard {
                field: None,
                pattern: tok.to_string(),
            },
        ))
    } else {
        Ok((input, SearchExpr::BareToken(tok.to_string())))
    }
}

fn field_name(input: &str) -> IResult<&str, &str> {
    recognize(take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '.'))(input)
}

fn quoted_or_bare(input: &str) -> IResult<&str, &str> {
    alt((
        delimited(char('"'), take_while1(|c| c != '"'), char('"')),
        delimited(char('\''), take_while1(|c| c != '\''), char('\'')),
        recognize(take_while1(|c: char| !c.is_whitespace() && c != '|' && c != ')')),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpl::ast::RplCommand;

    #[test]
    fn parses_stats_pipeline() {
        let q = parse_rpl(r#"platform="android" | stats count by parser | head 10"#).unwrap();
        assert!(matches!(q.commands[0], RplCommand::Stats { .. }));
    }

    #[test]
    fn parses_fields_comma_separated() {
        let q = parse_rpl(
            r#"bundle_id=* | fields timestamp, source, bundle_id | head 10"#,
        )
        .unwrap();
        assert!(matches!(
            q.commands[0],
            RplCommand::Fields { ref names } if names == &["timestamp", "source", "bundle_id"]
        ));
    }

    #[test]
    fn parses_fields_space_separated_after_rename() {
        parse_rpl(r#"fields package message"#).unwrap();
        parse_rpl(r#"platform="android" | rename bundle_id AS package | fields package message"#).unwrap();
    }

    #[test]
    fn parses_bang_field_negation() {
        let q = parse_rpl(
            r#"installer=* !installer="com.android.vending" !installer="null" | head 10"#,
        )
        .unwrap();
        assert!(matches!(q.search, SearchExpr::And(_)));
    }

    #[test]
    fn parses_fields_bitchat_hunt() {
        parse_rpl(
            r#"bundle_id=*bitchat* | fields timestamp, source, bundle_id, parser, action, message | sort -timestamp | head 100"#,
        )
        .unwrap();
    }

    #[test]
    fn parses_stats_by_multiple_fields_comma() {
        let q = parse_rpl(
            r#"source="case-001" parser="Network" | stats count by src_ip, dest_ip | head 50"#,
        )
        .unwrap();
        match &q.commands[0] {
            RplCommand::Stats { by, .. } => {
                assert_eq!(by, &["src_ip", "dest_ip"]);
            }
            _ => panic!("expected stats"),
        }
    }

    #[test]
    fn parses_last_time_modifier() {
        let q = parse_rpl(r#"last 24h platform="ios""#).unwrap();
        assert!(q.time_range.is_some());
        assert!(!q.is_broad_search());
    }

    #[test]
    fn parses_rex() {
        let q = parse_rpl(r#"platform="android" | rex ip=(\d+\.\d+\.\d+\.\d+) field=message"#).unwrap();
        assert!(matches!(q.commands[0], RplCommand::Rex { .. }));
    }

    #[test]
    fn parses_join() {
        let q = parse_rpl(
            r#"platform="android" | join device_id [ platform="ios" | head 5 ]"#,
        )
        .unwrap();
        assert!(matches!(q.commands[0], RplCommand::Join { .. }));
    }

    #[test]
    fn parses_not() {
        let q = parse_rpl(r#"platform="android" NOT parser="foo""#).unwrap();
        assert!(matches!(q.search, SearchExpr::And(_)));
    }

    #[test]
    fn parses_in_list() {
        let q = parse_rpl(r#"platform IN ("android", "ios")"#).unwrap();
        assert!(matches!(q.search, SearchExpr::In { negate: false, .. }));
    }

    #[test]
    fn parses_now_minus_time() {
        let q = parse_rpl(r#"now-7d platform="android""#).unwrap();
        assert!(q.time_range.is_some());
    }

    #[test]
    fn parses_rename_lookup_eval_expr() {
        let q = parse_rpl(
            r#"platform="android" | eval risk=if(severity="high",1,0) | rename bundle_id AS package | lookup src_ip"#,
        )
        .unwrap();
        assert_eq!(q.commands.len(), 3);
    }

    #[test]
    fn last_time_then_pipe_stats_needs_wildcard() {
        assert!(parse_rpl(r#"last 24h | stats count"#).is_err());
        let q = parse_rpl(r#"last 24h * | stats count"#).unwrap();
        assert!(matches!(q.commands[0], RplCommand::Stats { .. }));
    }

    #[test]
    fn parses_pipe_search_as_where() {
        let q = parse_rpl(r#"source="case-f58543db" | search user="cameraserver""#).unwrap();
        assert!(matches!(q.commands[0], RplCommand::Where(_)));
        assert_eq!(q.commands.len(), 1);
        assert_eq!(q.literal_field_eq("source").as_deref(), Some("case-f58543db"));
    }

    #[test]
    fn parses_case_entity_drilldown_with_lookups() {
        parse_rpl(
            r#"source="case-f58543db" | search user="cameraserver" | lookup src_ip | lookup geo dest_ip | lookup play bundle_id | lookup vt src_ip | lookup vt dest_ip | lookup vt destination_domain | lookup vt file_hash"#,
        )
        .unwrap();
    }

    #[test]
    fn parses_timechart_avg_field() {
        let q = parse_rpl(
            r#"source="case-1" parser="powerlogs" | timechart span=1h avg raw_level"#,
        )
        .unwrap();
        match &q.commands[0] {
            RplCommand::Timechart {
                agg,
                field,
                span,
                ..
            } => {
                assert_eq!(agg, "avg");
                assert_eq!(field.as_deref(), Some("raw_level"));
                assert_eq!(span, "1h");
            }
            _ => panic!("expected timechart"),
        }
        let q2 = parse_rpl(
            r#"source="case-1" | timechart span=15m avg(raw_level) by device_id limit=0"#,
        )
        .unwrap();
        match &q2.commands[0] {
            RplCommand::Timechart { agg, field, by, .. } => {
                assert_eq!(agg, "avg");
                assert_eq!(field.as_deref(), Some("raw_level"));
                assert_eq!(by.as_deref(), Some("device_id"));
            }
            _ => panic!("expected timechart"),
        }
    }
}
