use v10_streaming::drain::DrainState;
use v10_streaming::column::{analyze_column, ColumnType};
use v10_streaming::config::StreamingConfig;
use std::collections::HashMap;

fn main() {
    let config = StreamingConfig::default();
    let mut drain = DrainState::new(config);

    // Read first 1000 lines of HDFS log
    let content = std::fs::read_to_string("test_logs/hdfs_50mb.log").unwrap();
    let lines: Vec<&str> = content.lines().take(1000).collect();

    // Track variables per template variable position
    // key = (template_id, var_position), value = list of values
    let mut var_columns: HashMap<(i32, usize), Vec<String>> = HashMap::new();

    for line in &lines {
        let (tid, template, vars) = drain.add_line(line);

        // Collect variables per column
        for (i, var) in vars.iter().enumerate() {
            var_columns.entry((tid, i)).or_default().push(var.clone());
        }
    }

    // Analyze each column
    println!("=== Column Analysis ===\n");

    let mut type_counts: HashMap<&str, usize> = HashMap::new();
    let mut blk_in_dict_count = 0;

    for ((tid, pos), values) in &var_columns {
        let refs: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        let (col_type, ratio) = analyze_column(&refs);

        let type_name = match col_type {
            ColumnType::Raw => "Raw",
            ColumnType::Dictionary => "Dictionary",
            ColumnType::TimestampClf => "TimestampClf",
            ColumnType::TimestampClfFragment => "TimestampClfFrag",
            ColumnType::TimestampIso => "TimestampIso",
            ColumnType::PrefixId => "PrefixId",
            ColumnType::Numeric => "Numeric",
            ColumnType::IPv4 => "IPv4",
            ColumnType::Path => "Path",
        };

        *type_counts.entry(type_name).or_default() += 1;

        // Check if this dictionary column contains blk_ values
        if col_type == ColumnType::Dictionary {
            let blk_count = values.iter().filter(|v| v.contains("blk_")).count();
            if blk_count > 0 {
                blk_in_dict_count += 1;
                println!("Template {} pos {}: {} (ratio {:.2}) - {} values, {} with blk_",
                    tid, pos, type_name, ratio, values.len(), blk_count);

                // Show sample values
                let samples: Vec<_> = values.iter().take(5).collect();
                println!("  Sample: {:?}", samples);

                // Debug why not PrefixId
                let prefix_count = values.iter().filter(|v| {
                    let re = regex::Regex::new(r#"^"?([a-zA-Z][a-zA-Z0-9]*)[-_](-?\d+)"?,?$"#).unwrap();
                    re.is_match(v)
                }).count();
                println!("  PrefixId matches: {}/{} ({:.1}%)", prefix_count, values.len(),
                    100.0 * prefix_count as f64 / values.len() as f64);

                // Check unique prefixes
                let re = regex::Regex::new(r#"^"?([a-zA-Z][a-zA-Z0-9]*)[-_](-?\d+)"?,?$"#).unwrap();
                let prefixes: std::collections::HashSet<_> = values.iter()
                    .filter_map(|v| re.captures(v))
                    .map(|c| c.get(1).unwrap().as_str().to_string())
                    .collect();
                println!("  Unique prefixes: {:?}", prefixes);
                println!();
            }
        }
    }

    println!("\n=== Summary ===");
    for (type_name, count) in &type_counts {
        println!("  {}: {} columns", type_name, count);
    }
    println!("  Columns with blk_ in Dictionary: {}", blk_in_dict_count);
}
