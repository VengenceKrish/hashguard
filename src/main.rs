/*File Integrity Analyser
======== Req ========
Satisfied:
- Accept a dir or log file: done
- Use a hashing algo to compute hashes for each log file: done
- On first use, store hashes in secure location: done
- Subsequent uses: compare the hashes against previous ones
- Clearly report discrepancies

Unsatisfied:
- Allow for manual reinit of log file integrity
- Make it executable in bash
*/

use std::fs::{File};
use std::io::{self, Read};
use sha2::{Sha256, Digest};
use rusqlite::{params, Connection};

fn compute_hash(mut file: File) -> String{ // Hashes the log file in Sha256
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");
    hasher.update(&buffer);
    format!("{:x}", hasher.finalize())
}

fn input_log_dir(filename: &str) -> std::io::Result<File>{ // Opens file
    let file = File::open(filename)?;
    Ok(file)
}

// Passes values to the database.
fn store_hash(conn: &Connection, filename: &str, hash_val: &str){
    conn.execute("INSERT OR REPLACE INTO file_hashes (filename, hash) VALUES (?1, ?2)", [filename, hash_val]).expect("Failed to store");
}

/* Will be used in 2 contexts. 
1: To check if the file has been hashed before. 
2: Comparing hashes to verify log file.*/
fn retrieve_hash(conn: &Connection, filename: &str) -> Option<String> { 
    let mut stmt = conn.prepare(
        "SELECT hash FROM file_hashes WHERE filename = ?1"
    ).expect("Failed to prepare statement");

    stmt.query_row(params![filename], |row| row.get(0)).ok()
}

fn log_discrepancy(conn: &Connection, filename: &str, stored_hash: &str, new_hash: &str, overwritten: bool){
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    conn.execute("INSERT INTO discrepancies (filename, stored_hash, new_hash, overwritten, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)", 
    params![filename, stored_hash, new_hash, overwritten, timestamp],).expect("Failed to log discrepancy!");
}

fn update_discrepancy(conn: &Connection, filename: &str) { // Only changes Overwrite from false to true
    conn.execute(
        "UPDATE discrepancies SET overwritten = true WHERE filename = ?1 
        ORDER BY timestamp DESC LIMIT 1",
        params![filename],
    ).expect("Failed to update discrepancy");
}

fn process_file(conn: &Connection, filename: &str){
    match input_log_dir(filename){
        Ok(file) => {
        println!("File opened successfully");
        let hash_val = compute_hash(file);
        // Checking file hashes. 
        let mut attempts = 0;
        match retrieve_hash(&conn, filename){
            None => {
                // New filename
                store_hash(&conn, filename, &hash_val);
                println!("Baseline hash stored for '{}'", filename);
            },
            Some(stored_hash) =>{
                if stored_hash == hash_val{
                    // No changes, ignore the new hash
                    println!("File '{}' has no modifications. No changes required.", filename);
                }
                else {
                    // Mismatch detected.
                    println!("WARNING: File '{}' has been modified!", filename);
                    log_discrepancy(&conn, filename, &stored_hash, &hash_val, false);
                    loop {
                        if attempts >= 3 {
                            println!("Maximum attempts reached. Aborting.");
                            break;
                        }
                        
                        println!("Would you like to overwrite the stored hash? (yes/no)");
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).expect("Failed to read input");
                        let input = input.trim().to_lowercase();
                        match input.as_str() {
                            "yes" => {
                                store_hash(&conn, filename, &hash_val);
                                println!("Hash updated successfully.");
                                update_discrepancy(&conn, filename); // Changes overwrite from false to true
                                break;
                            },
                            "no" => {
                                println!("Hash unchanged. Discrepancy logged.");
                                break;
                            },
                            _ => {
                                attempts += 1;
                                println!("Invalid input. Please enter 'yes' or 'no'. ({}/3 attempts)", attempts);
                            },
                        }
                    }
                }
            } 

        }
        },
        Err(e) => eprintln!("Error opening file: {}", e),
    }
}

fn main() {
    // Setting up the db.
    let conn = Connection::open("hashes.db").expect("Failed to open database");
    conn.execute( // Has Table
        "CREATE TABLE IF NOT EXISTS file_hashes (
            filename TEXT PRIMARY KEY,
            hash TEXT NOT NULL
        )",[],).expect("Failed to create table");

    conn.execute( // Discrepancy table
    "CREATE TABLE IF NOT EXISTS discrepancies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        stored_hash TEXT NOT NULL,
        new_hash TEXT NOT NULL,
        overwritten BOOLEAN NOT NULL,
        timestamp TEXT NOT NULL
    )", [],).expect("Failed to create discrepancies table");

    // File input
    let mut path = String::new();
    println!("Enter log file or directory PATH"); // Implement the path thing later
    io::stdin().read_line(&mut path).expect("failed to readline");
    let path= path.trim(); // remove trailing newline

    let metadata = std::fs::metadata(path).expect("Failed to read path");
    if metadata.is_dir(){
        for entry in std::fs::read_dir(path).expect("Failed to read dir"){
            let entry = entry.expect("Failed to read entry");
            let entry_path = entry.path();
            if entry_path.extension().map(|e| e == "log").unwrap_or(false){
                let filename = entry_path.to_str().expect("Invalid Path");
                println!("Processing '{}'...", filename);
                process_file(&conn, filename);
            }
        }
    } else {
        process_file(&conn, path);
    }
}
