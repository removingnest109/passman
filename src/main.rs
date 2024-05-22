use eframe::egui;
use rusqlite::{params, Connection};
use std::fs;
use dirs::data_dir;

mod pbkdf2_aes;
use pbkdf2_aes::{derive_key_from_password, encrypt, decrypt, PasswordEntry};

fn main() {
    let options = eframe::NativeOptions::default();

    eframe::run_native("Password Manager", options, Box::new(|_cc| Box::<MyApp>::default()));
}

struct MyApp {
    logged_in: bool,
    master_password: String,
    aes_key: Option<[u8; 32]>,
    site: String,
    username: String,
    password: String,
    conn: Connection,
    passwords: Vec<PasswordEntry>,
    show_passwords: Vec<bool>,
}

impl Default for MyApp {
    fn default() -> Self {
        let data_dir = data_dir().unwrap().join("passman");
        fs::create_dir_all(&data_dir).expect("Failed to create data directory");
        let db_path = data_dir.join("passwords.db");
        let conn = Connection::open(&db_path).expect("Failed to open database");
        conn.execute(
            "CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )",
            [],).expect("Failed to create table");
        Self {
            logged_in: false,
            master_password: String::new(),
            aes_key: None,
            site: String::new(),
            username: String::new(),
            password: String::new(),
            conn,
            passwords: Vec::new(),
            show_passwords: Vec::new(),
        }
    }
}

impl MyApp {
    fn load_passwords(&mut self) -> Vec<PasswordEntry> {
        let mut stmt = self.conn.prepare("SELECT id, site, username, password FROM passwords").expect("Failed to prepare statement");
        let rows = stmt.query_map([], |row| {
            Ok(PasswordEntry {
                id: row.get(0)?,
                site: row.get(1)?,
                username: row.get(2)?,
                password: row.get(3)?})})
	    .expect("Failed to query passwords");
        rows.map(|entry| entry.unwrap()).collect()
    }

    fn add_entry_to_db(&mut self, entry: &PasswordEntry) {
        self.conn.execute(
            "INSERT INTO passwords (site, username, password) VALUES (?1, ?2, ?3)",
            params![entry.site, entry.username, entry.password],)
	    .expect("Failed to insert password entry");
    }

    fn delete_entry_from_db(&mut self, id: i64) {
	self.conn.execute("DELETE FROM passwords WHERE id = ?1", params![id],).expect("Failed to delete password entry");
	self.conn.execute("VACUUM", [],).expect("Failed to execute VACUUM command");
    }

    fn update_password_visibility(&mut self) {
        self.show_passwords = vec![false; self.passwords.len()];
    }

    fn decrypt_all_passwords(&mut self) {
        if let Some(_key) = self.aes_key {
            let decrypted_passwords: Vec<PasswordEntry> = self.load_passwords().into_iter().map(|entry| {
                let decrypted_password = decrypt(&self.master_password, &entry.password).expect("Decryption failed");
                PasswordEntry {
                    id: entry.id,
                    site: entry.site,
                    username: entry.username,
                    password: decrypted_password,}})
		.collect();
            self.passwords = decrypted_passwords;
            self.update_password_visibility();
        }
    }

    fn attempt_login(&mut self) {
        let key = derive_key_from_password(&self.master_password, &[0; 16]);
        self.aes_key = Some(key);
        self.logged_in = true;
        self.decrypt_all_passwords();
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {

        egui::CentralPanel::default().show(ctx, |ui| {

	    ctx.set_visuals(egui::Visuals::dark());

            if !self.logged_in {
                ui.vertical_centered(|ui| {
                    ui.heading("Login");
                    let password_response = ui.add(egui::TextEdit::singleline(&mut self.master_password)
						   .password(true)
						   .hint_text("Master Password"));
                    if password_response.lost_focus() && ui.input().key_pressed(egui::Key::Enter) {
                        self.attempt_login();
                    }
                });
	    }

	    else {
		egui::ScrollArea::both().auto_shrink([false; 2]).show(ui, |ui| {

		    ui.heading("Password Manager");

		    egui::Grid::new("password_entry_ui").num_columns(2).show(ui, |ui| {

			ui.label("Site:");
			ui.text_edit_singleline(&mut self.site);
			ui.end_row();

			ui.label("Username:");
			ui.text_edit_singleline(&mut self.username);
			ui.end_row();

			ui.label("Password:");
			ui.text_edit_singleline(&mut self.password);
			ui.end_row();

			if ui.button("Add Entry").clicked() {
			    if let Some(_key) = self.aes_key {
				let encrypted_password = encrypt(&self.master_password, &self.password)
				    .expect("Encryption failed");
				let entry = PasswordEntry {
				    id: 0,
				    site: self.site.clone(),
				    username: self.username.clone(),
				    password: encrypted_password,
				};
				self.add_entry_to_db(&entry);
				self.site.clear();
				self.username.clear();
				self.password.clear();
				self.decrypt_all_passwords();
			    }
			}
		    });

		    ui.separator();

		    ui.heading("Stored Passwords:");

		    egui::Grid::new("password_display_ui").num_columns(6).striped(true).show(ui, |ui| {

			let passwords_clone = self.passwords.clone();
			for (i, entry) in passwords_clone.iter().enumerate() {

			    ui.label(format!("Site: {}", entry.site));

			    ui.label(format!("Username: {}", entry.username));

			    if self.show_passwords[i] {
				ui.label(format!("Password: {}", entry.password));
			    } else {
				ui.label("Password: ********");
			    }

			    if ui.button("Show/Hide").clicked() {
				self.show_passwords[i] = !self.show_passwords[i];
			    }

			    if ui.button("Copy").clicked() {
				ui.output().copied_text = entry.password.clone();
			    }

			    if ui.button("Delete").clicked() {
				let id = entry.id;
				self.delete_entry_from_db(id.into());
				self.passwords = self.load_passwords();
				self.update_password_visibility();
			    }

			    ui.end_row();
			}
		    });
		});
	    }
	});
    }
}
