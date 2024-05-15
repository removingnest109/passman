use eframe::egui;
use std::fs;
use std::path::PathBuf;
use dirs::data_dir;

mod passwordmanager;
use passwordmanager::{PasswordManager, PasswordEntry};

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Password Manager",
        options,
        Box::new(|_cc| Box::new(MyApp::default())),
    );
}

struct MyApp {
    passwordmanager: PasswordManager,
    master_password: String,
    site: String,
    username: String,
    password: String,
    data_dir: PathBuf,
}

impl Default for MyApp {
    fn default() -> Self {
        let data_dir = data_dir().unwrap().join("rust-passwordmanager");
        fs::create_dir_all(&data_dir).expect("Failed to create data directory");
        Self {
            passwordmanager: PasswordManager::new(),
            master_password: String::new(),
            site: String::new(),
            username: String::new(),
            password: String::new(),
            data_dir,
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Password Manager");

            ui.horizontal(|ui| {
                ui.label("Master Password:");
                ui.text_edit_singleline(&mut self.master_password);
            });

            if ui.button("Load Passwords").clicked() {
                let file_path = self.data_dir.join("passwords.json");
                if let Ok(manager) = PasswordManager::load_from_file(&file_path, &self.master_password) {
                    self.passwordmanager = manager;
                }
            }

            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Site:");
                ui.text_edit_singleline(&mut self.site);
            });
            ui.horizontal(|ui| {
                ui.label("Username:");
                ui.text_edit_singleline(&mut self.username);
            });
            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.text_edit_singleline(&mut self.password);
            });

            if ui.button("Add Entry").clicked() {
                self.passwordmanager.add_entry(
                    self.site.clone(),
                    self.username.clone(),
                    self.password.clone(),
                );
                self.site.clear();
                self.username.clear();
                self.password.clear();
            }

            if ui.button("Save Passwords").clicked() {
                let file_path = self.data_dir.join("passwords.json");
                self.passwordmanager.save_to_file(&file_path, &self.master_password).expect("Failed to save passwords");
            }

            ui.separator();

            ui.heading("Stored Passwords:");
            for entry in &self.passwordmanager.entries {
                ui.horizontal(|ui| {
                    ui.label(format!("Site: {}, Username: {}, Password: {}", entry.site, entry.username, entry.password));
                });
            }
        });
    }
}
