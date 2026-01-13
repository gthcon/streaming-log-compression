use v10_streaming::drain::DrainState;
use v10_streaming::column::{analyze_column, ColumnType};
use v10_streaming::config::StreamingConfig;
use std::collections::HashMap;

fn main() {
    let config = StreamingConfig::default();
    let mut drain = DrainState::new(config);

    // Read all lines
    let content = std::fs::read_to_string("test_logs/hdfs_50mb.log").unwrap();
    let lines: Vec<&str> = content.lines().collect();
    
    println!("Total lines: {}", lines.len());

    // Track templates
    let mut template_counts: HashMap<String, usize> = HashMap::new();
    let mut template_ids: HashMap<String, i32> = HashMap::new();
    
    // Track column types per template
    let mut var_columns: HashMap<(i32, usize), Vec<String>> = HashMap::new();

    for line in &lines {
        let (tid, template, vars) = drain.add_line(line);
        
        *template_counts.entry(template.clone()).or_default() += 1;
        template_ids.insert(template, tid);

        for (i, var) in vars.iter().enumerate() {
            var_columns.entry((tid, i)).or_default().push(var.clone());
        }
    }

    // Sort templates by count
    let mut sorted: Vec<_> = template_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));

    println!("\n=== Top 20 Templates ===\n");
    for (template, count) in sorted.iter().take(20) {
        let tid = template_ids.get(*template).unwrap_or(&-1);
        println!("tid={:3} count={:6} template='{}'", tid, count, template.chars().take(80).collect::<String>());
    }

    println!("\n=== Template Count Distribution ===");
    println!("Total unique templates: {}", template_counts.len());
    
    // Analyze columns
    println!("\n=== Column Type Analysis ===");
    let mut type_counts: HashMap<&str, usize> = HashMap::new();
    let mut raw_count = 0;
    let mut dict_high_cardinality = 0;
    
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
        
        if col_type == ColumnType::Raw {
            raw_count += 1;
            if values.len() > 100 {
                let sample: Vec<_> = values.iter().take(3).collect();
                println!("Raw column (tid={}, pos={}): {} values, sample={:?}", 
                    tid, pos, values.len(), sample);
            }
        }
        
        if col_type == ColumnType::Dictionary {
            let unique: std::collections::HashSet<_> = values.iter().collect();
            if unique.len() > 100 {
                dict_high_cardinality += 1;
                println!("High-cardinality dict (tid={}, pos={}): {} unique/{} total", 
                    tid, pos, unique.len(), values.len());
            }
        }
    }

    println!("\n=== Column Type Summary ===");
    for (type_name, count) in &type_counts {
        println!("  {}: {} columns", type_name, count);
    }
    println!("  High-cardinality Dictionary: {}", dict_high_cardinality);
}
