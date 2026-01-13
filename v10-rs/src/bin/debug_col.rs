use v10_streaming::column::{analyze_column, ColumnEncoder};

fn main() {
    let col1 = ["6", "", "2", ""];
    let refs: Vec<&str> = col1.iter().map(|s| *s).collect();
    
    println!("Column values: {:?}", col1);
    let (col_type, score) = analyze_column(&refs);
    println!("Detected type: {:?}, score: {}", col_type, score);
    
    // Now let's encode and decode
    let encoded = ColumnEncoder::encode(&refs);
    println!("Encoded: {:?}", encoded);
    
    let decoded = ColumnEncoder::decode(&encoded, 4).unwrap();
    println!("Decoded: {:?}", decoded);
}
