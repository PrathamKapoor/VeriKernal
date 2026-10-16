//! Parse Rust source contracts with syn. O(bytes) time and O(nodes) space.
use std::{env, fs};
use syn::{
    visit::{self, Visit},
    Attribute, ImplItemFn, ItemFn, ItemStruct, ReturnType, Visibility,
};
struct Audit {
    issues: Vec<String>,
    functions: usize,
}
/// Check that a Rust item carries a documentation attribute. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn documented(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("doc"))
}
impl<'a> Visit<'a> for Audit {
    /// Inspect a function declaration for required source contracts. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn visit_item_fn(&mut self, node: &'a ItemFn) -> () {
        if matches!(node.vis, Visibility::Public(_)) {
            self.functions += 1;
            if !documented(&node.attrs) {
                self.issues
                    .push(format!("function documentation: {}", node.sig.ident));
            }
            if matches!(node.sig.output, ReturnType::Default) {
                self.issues
                    .push(format!("explicit unit return: {}", node.sig.ident));
            }
        }
        visit::visit_item_fn(self, node);
    }
    /// Inspect an implementation method for required source contracts. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn visit_impl_item_fn(&mut self, node: &'a ImplItemFn) -> () {
        if matches!(node.vis, Visibility::Public(_)) {
            self.functions += 1;
            if !documented(&node.attrs) {
                self.issues
                    .push(format!("method documentation: {}", node.sig.ident));
            }
            if matches!(node.sig.output, ReturnType::Default) {
                self.issues
                    .push(format!("explicit unit return: {}", node.sig.ident));
            }
        }
        visit::visit_impl_item_fn(self, node);
    }
    /// Inspect a structure declaration for required documentation. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn visit_item_struct(&mut self, node: &'a ItemStruct) -> () {
        if matches!(node.vis, Visibility::Public(_)) && !documented(&node.attrs) {
            self.issues
                .push(format!("struct documentation: {}", node.ident));
        }
        visit::visit_item_struct(self, node);
    }
}
/// Parse command-line arguments and return the workflow status. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn main() -> () {
    let mut issues = Vec::new();
    let mut files = 0;
    let mut functions = 0;
    for path in env::args().skip(1) {
        match fs::read_to_string(&path)
            .map_err(|error| error.to_string())
            .and_then(|text| syn::parse_file(&text).map_err(|error| error.to_string()))
        {
            Ok(tree) => {
                files += 1;
                let mut audit = Audit {
                    issues: Vec::new(),
                    functions: 0,
                };
                audit.visit_file(&tree);
                functions += audit.functions;
                for issue in audit.issues {
                    issues.push(format!("{}: {}", path, issue));
                }
            }
            Err(error) => issues.push(format!("{}: Rust syntax: {}", path, error)),
        }
    }
    println!(
        "{}",
        serde_json::json!({"parsed_files":files,"public_functions":functions,"issues":issues})
    );
    if !issues.is_empty() {
        std::process::exit(1);
    }
}
