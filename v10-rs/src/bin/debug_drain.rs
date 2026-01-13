use v10_streaming::drain::DrainState;
use v10_streaming::config::StreamingConfig;

fn main() {
    let config = StreamingConfig::default();
    let mut drain = DrainState::new(config);
    
    let lines = [
        "hub 1-0:1.0: 6 ports detected",
        "hub 1-0:1.0: USB hub found",
        "hub 1-3:1.0: 2 ports detected",
        "hub 1-3:1.0: USB hub found",
    ];
    
    for line in &lines {
        let (tid, template, vars) = drain.add_line(line);
        println!("Line: {}", line);
        println!("  tid: {}, template: '{}', vars: {:?}", tid, template, vars);
    }
    
    println!("\nAll templates:");
    for (id, tmpl) in drain.get_templates() {
        println!("  {}: '{}'", id, tmpl);
    }
}
