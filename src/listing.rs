use crate::VERSION_STRING;
use chrono::{DateTime, Local};
use std::{io, path::Path};
use tokio::fs;

const HTML_TEMPLATE: &str = include_str!("../static/index.html");

const FILE_LIST_TABLE_TEMPLATE: &str = r###"
<table style="margin-left: 1em">
    <thead style="font-style: italic;">
        <tr>
            <th style="padding-right: 1em;">File Name</th>
            <th style="padding-right: 1em;">Size</th>
            <th style="padding-right: 1em;">Last Modified</th>
        </tr>
    </thead>
    <tbody>
        {{file_list}}{{placeholder}}
    </tbody>
</table>
"###;

const EMPTY_LIST: &str = "<tr><td><i>&lt;empty&gt;</i><td></tr>";

const FILE_LIST_TABLE_ROW: &str = r###"
<tr>
    <td style="padding-right: 1em;"><a href="{{href}}">{{name}}</a></td>
    <td style="padding-right: 1em;">{{size}}</td>
    <td style="padding-right: 1em;">{{modified}}</td>
</tr>
"###;

pub const BREADCRUMBS_TEMPLATE: &str = r###"
<ul id="breadcrumbs" style="display: flex;list-style: none;align-items: center;padding-inline: unset;margin-left: 1em;">
    {{items}}
</ul>
"###;

pub const BREADCRUMBS_ITEM: &str = r###"
<li class="breadcrums-item">
    <a href="{{href}}">
        <span class="separator" style="padding: 0 5px 0 5px;">/</span>
        <span>{{label}}</span>
    </a>
</li>
"###;

/// Render the directory's breadcrumb navigation.
pub fn breadcrumbs(parent: &Path, root: &Path) -> String {
    let mut items = BREADCRUMBS_ITEM
        .replace("{{href}}", "/")
        .replace("{{label}}", "ROOT");
    let mut link = String::from("/");
    if let Ok(path) = parent.strip_prefix(root) {
        for piece in path.iter() {
            let label = piece.to_string_lossy();
            link.push_str(&urlencoding::encode(&label));
            link.push('/');
            items.push_str(
                &BREADCRUMBS_ITEM
                    .replace("{{href}}", &link)
                    .replace("{{label}}", &escape_html(&label)),
            );
        }
    }
    BREADCRUMBS_TEMPLATE.replace("{{items}}", &items)
}

pub(crate) async fn directory_listing(path: &Path, relative: &Path) -> io::Result<String> {
    let mut entries = fs::read_dir(path).await?;
    let mut prefix = String::from("/");
    for component in relative.iter() {
        prefix.push_str(&urlencoding::encode(&component.to_string_lossy()));
        prefix.push('/');
    }

    let mut rows = String::new();
    while let Some(entry) = entries.next_entry().await? {
        let metadata = match entry.metadata().await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let name = entry.file_name();
        let label = name.to_string_lossy();
        let href = format!("{prefix}{}", urlencoding::encode(&label));
        let modified = metadata
            .modified()
            .ok()
            .map(|time| {
                DateTime::<Local>::from(time)
                    .format("%b %d %Y - %H:%M")
                    .to_string()
            })
            .unwrap_or_default();
        rows.push_str(
            &FILE_LIST_TABLE_ROW
                .replace("{{href}}", &href)
                .replace("{{size}}", &metadata.len().to_string())
                .replace("{{modified}}", &modified)
                .replace("{{name}}", &escape_html(&label)),
        );
    }
    let placeholder = if rows.is_empty() { EMPTY_LIST } else { "" };
    let table = FILE_LIST_TABLE_TEMPLATE
        .replace("{{placeholder}}", placeholder)
        .replace("{{file_list}}", &rows);
    let title = format!("File list under {}", escape_html(&prefix));
    Ok(HTML_TEMPLATE
        .replace("{{version}}", VERSION_STRING.as_str())
        .replace("{{title}}", &title)
        .replace("{{body}}", &table)
        .replace("{{header}}", &breadcrumbs(relative, Path::new(""))))
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
        .replace('{', "&#123;")
}
