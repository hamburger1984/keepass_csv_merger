use csv::{Reader, StringRecord, Writer};
use std::{
    collections::HashMap,
    fs,
    io::{stdin, stdout, BufReader, BufWriter, Write},
    path::Path,
    process::{Command, Stdio},
};
use tempdir::TempDir;

use tinyfiledialogs::select_folder_dialog;

const KEEPASS_CLI: &str = "keepassxc-cli";
const HEADER_KEY: &str = "HEAD";

fn main() -> Result<(), &'static str> {
    let Ok(cli_help) = Command::new(KEEPASS_CLI).arg("--help").output() else {return Err("Could not find the keepaxx cli");};
    if !cli_help.status.success() {
        return Err("Running the keepass cli failed");
    }

    let Some(kx_folder) = select_folder_dialog("Select folder to load Keepass DBs from", ".") else { 
        return Err("No folder selected to read from");
    };
    println!("Selected {kx_folder}");

    let Ok(tmp_dir) = TempDir::new("merger") else { return Err("Failed to create a temp dir") };
    println!("Using temp dir {}", tmp_dir.path().to_string_lossy());

    let Ok(entries) = fs::read_dir(&kx_folder) else { return Err("Failed to read dir"); };

    print!("Please enter your password to continue: ");
    if stdout().flush().is_err() {
        return Err("Failed to flush STDOUT");
    }

    let mut pass = String::new();
    if stdin().read_line(&mut pass).is_err() {
        return Err("Failed to read password from STDIN");
    }

    let mut merged: HashMap<String, StringRecord> = HashMap::new();

    for entry in entries {
        let Ok(entry) = entry else { return Err("Failed to get dir entry"); };
        let path = entry.path();
        if !path.is_file() {
            println!("Skipping non-file {}", path.to_string_lossy());
            continue;
        }
        if "kdbx".ne(path.extension().unwrap_or_default()) {
            println!("Skipping file {}", path.to_string_lossy());
            continue;
        }
        println!("Using file {}", path.to_string_lossy());

        let Ok(mut to_csv) = Command::new(KEEPASS_CLI)
                    .arg("export").arg("-q").arg("-f").arg("csv").arg(path)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn() else {return Err("Failed to convert to csv");};

        let csv_in = to_csv.stdin.take().unwrap();
        let mut writer = BufWriter::new(csv_in);
        if writer.write_all(pass.as_bytes()).is_err() || writer.flush().is_err() {
            return Err("Failed to write password to keepass");
        }

        let csv_out = to_csv.stdout.take().unwrap();
        let reader = BufReader::new(csv_out);

        let mut csv_reader = Reader::from_reader(reader);

        if !merged.contains_key(HEADER_KEY) {
            let Ok(headers) = csv_reader.headers() else { return Err("Failed to read headers") };
            merged.insert(HEADER_KEY.to_owned(), headers.clone());
        }

        let mut r_count = 0;
        for r in csv_reader.records() {
            let Ok(row) = r else { return Err("Failed to read record") };

            let group = row.get(0).unwrap();

            if group.contains("Papierkorb") || group.contains("deprecated") {
                continue;
            }

            let title = row.get(1).unwrap();
            let user = row.get(2).unwrap();
            let last_modified = row.get(8).unwrap();

            //println!("{}: {} .. {}", title, user, last_modified);

            // Title:Username
            let key = format!("{}:{}", title, user);

            if merged.contains_key(&key) {
                if merged[&key].get(8).unwrap() < last_modified {
                    merged.insert(key, row);
                }
            } else {
                merged.insert(key, row);
            }

            r_count += 1;
        }
        println!(" > {r_count} records");

        to_csv.kill();
    }

    let Some(header) = merged.get(HEADER_KEY) else {return Err("Failed to find header")};

    let out_file = Path::new(&kx_folder).join("merged.csv");
    let Ok(mut merged_writer) = Writer::from_path(out_file) else {return Err("Failed to open target file")};

    merged_writer.write_record(header);

    let mut total = 0;
    for (key, record) in merged {
        if key.eq(HEADER_KEY) {
            continue;
        }
        //println!("{:?}", &record);
        merged_writer.write_record(&record);
        total += 1;
    }
    merged_writer.flush();
    println!("{total} records written");

    Ok(())
}
