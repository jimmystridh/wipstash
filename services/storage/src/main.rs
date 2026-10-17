use std::{env, fs, path::PathBuf};
use wipstash_storage::{Budget, Plan};
fn run() -> Result<serde_json::Value, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let result=match args.first().map(String::as_str){
  Some("usage") if args.len()>=2=>serde_json::to_value(wipstash_storage::usage(&args[1..].iter().map(PathBuf::from).collect::<Vec<_>>(),1_000_000)?),
  Some("admit") if args.len()==7=>{let number=|i:usize|args[i].parse::<u64>().map_err(|_|"invalid unsigned integer".to_owned());serde_json::to_value(wipstash_storage::admit(&[PathBuf::from(&args[1])],Budget{max_bytes:number(2)?,max_entries:number(3)?,reserve_bytes:number(4)?},number(5)?,number(6)?)?)},
  Some("plan") if args.len()==4=>serde_json::to_value(wipstash_storage::plan(&PathBuf::from(&args[1]),&args[2],args[3].parse().map_err(|_|"invalid retention seconds")?)?),
  Some("apply") if args.len()==4&&args[3]=="--confirm-unreachable-loose-removal"=>{let metadata=fs::metadata(&args[2]).map_err(|e|e.to_string())?;if metadata.len()>64*1024*1024{return Err("plan file too large".into())}let plan:Plan=serde_json::from_slice(&fs::read(&args[2]).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;serde_json::to_value(wipstash_storage::apply(&PathBuf::from(&args[1]),&plan)?)},
  _=>return Err("usage: wipstash-storage usage ABS_ROOT... | admit ABS_ROOT MAX_BYTES MAX_ENTRIES RESERVE_BYTES INCOMING_BYTES INCOMING_ENTRIES | plan ABS_STATE REPOSITORY MINIMUM_AGE_SECONDS | apply ABS_STATE PLAN_JSON --confirm-unreachable-loose-removal".into())
 };
    result.map_err(|e| e.to_string())
}
fn main() {
    match run() {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
    }
}
