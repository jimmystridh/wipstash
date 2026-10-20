use super::{
    context::{self, Context},
    fail, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;

#[derive(Serialize, Deserialize)]
pub struct Index {
    pub generation: u64,
    pub base_tree: String,
    pub tree: String,
}

pub fn index(context: &Context) -> Result<Index> {
    let (generation, base_tree) = context.workspace()?;
    let path = context.repo.root.join(".wip/index.json");
    if path.exists() {
        let index: Index = serde_json::from_value(context::read_json(&path)?).map_err(fail)?;
        if index.generation != generation || index.base_tree != base_tree {
            return Err("staging_generation_changed: inspect the retained operation; unstage with wip restore --staged . after resolving it".into());
        }
        Ok(index)
    } else {
        Ok(Index {
            generation,
            tree: base_tree.clone(),
            base_tree,
        })
    }
}
pub fn add(context: &Context, paths: &[String]) -> Result<Value> {
    let mut index = index(context)?;
    index.tree = context
        .git()
        .stage(&context.repo.root, &index.tree, paths)?;
    let review = tempfile::tempdir_in(&context.repo.state).map_err(fail)?;
    context.git().materialize(&index.tree, review.path())?;
    context.git().set_ref(
        &format!("refs/wipstash/cli-index/{}", context.repo.workspace),
        &index.tree,
        None,
    )?;
    context::write_json(&context.repo.root.join(".wip/index.json"), &index)?;
    Ok(json!({"ok":true,"staged":changes(context,&index.base_tree,&index.tree)?}))
}
pub fn restore(context: &Context, paths: &[String]) -> Result<Value> {
    if paths.iter().any(|p| p == ".") {
        clear(context)?;
        return Ok(json!({"ok":true,"staged":[],"files_changed":false}));
    }
    let mut index = index(context)?;
    let original = tempfile::tempdir_in(&context.repo.state).map_err(fail)?;
    context
        .git()
        .materialize(&index.base_tree, original.path())?;
    index.tree = context.git().stage(original.path(), &index.tree, paths)?;
    context::write_json(&context.repo.root.join(".wip/index.json"), &index)?;
    Ok(
        json!({"ok":true,"staged":changes(context,&index.base_tree,&index.tree)?,"files_changed":false}),
    )
}
pub fn clear(context: &Context) -> Result<()> {
    let path = context.repo.root.join(".wip/index.json");
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(fail(e)),
    }
}
pub fn require_empty(context: &Context) -> Result<()> {
    let i = index(context)?;
    if i.tree != i.base_tree {
        return Err("staged_changes_present: commit or unstage before merging".into());
    }
    Ok(())
}
pub fn changes(context: &Context, base: &str, head: &str) -> Result<Value> {
    let bytes = context.git().run(
        &[
            "diff-tree",
            "--no-commit-id",
            "--no-renames",
            "--name-status",
            "-r",
            "-z",
            base,
            head,
        ],
        None,
    )?;
    let fields = bytes
        .split(|b| *b == 0)
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>();
    if fields.len() % 2 != 0 {
        return Err("invalid_diff_output".into());
    }
    Ok(Value::Array(fields.as_chunks::<2>().0.iter().map(|pair|json!({"change":String::from_utf8_lossy(pair[0]),"path":String::from_utf8_lossy(pair[1])})).collect()))
}
pub fn status(context: &Context, quick: bool) -> Result<Value> {
    let mut value = context
        .call(json!({"op":"status","workspace":context.repo.workspace,"inspect_files":!quick}));
    let index = index(context)?;
    value["staged"] = changes(context, &index.base_tree, &index.tree)?;
    value["unstaged"] = if quick {
        Value::Null
    } else {
        changes(
            context,
            &index.tree,
            &context.git().capture(&context.repo.root)?,
        )?
    };
    Ok(value)
}
