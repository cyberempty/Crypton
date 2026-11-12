use crate::ops::{self, Prepared};
use crate::stego::{self, Extracted};
use crate::util::{CryptonError as E, Progress, Result};
use eframe::egui::{
    self, pos2, vec2, Align2, Color32, CornerRadius, CursorIcon, FontId, Rect, RichText, Sense, Shape, Stroke,
    StrokeKind, Vec2,
};
use std::f32::consts::PI;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

// Palette: black, gray and white; color is reserved for actions.
const BG: Color32 = Color32::from_rgb(11, 11, 13);
const CARD: Color32 = Color32::from_rgb(21, 21, 24);
const CARD_HOVER: Color32 = Color32::from_rgb(28, 28, 33);
const BORDER: Color32 = Color32::from_rgb(42, 42, 48);
const INPUT_BG: Color32 = Color32::from_rgb(9, 9, 11);
const TEXT: Color32 = Color32::from_rgb(242, 242, 245);
const MUTED: Color32 = Color32::from_rgb(140, 140, 150);
const NEUTRAL: Color32 = Color32::from_rgb(38, 38, 44);
const GREEN: Color32 = Color32::from_rgb(34, 164, 93);
const BLUE: Color32 = Color32::from_rgb(59, 130, 246);
const AMBER: Color32 = Color32::from_rgb(245, 165, 36);
const VIOLET: Color32 = Color32::from_rgb(139, 92, 246);
const RED: Color32 = Color32::from_rgb(248, 113, 113);
const MAX_W: f32 = 1200.0;
const LOGO_PNG: &[u8] = include_bytes!("../assets/logo.png");

enum Msg {
    Success { title: String, text: String },
    Info(Result<String>),
    DecryptReady(Prepared),
    ExtractReady(Extracted),
    Failed(E),
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Info,
    Success,
    Warning,
    Error,
}

impl Kind {
    fn color(self) -> Color32 {
        match self {
            Kind::Info => BLUE,
            Kind::Success => GREEN,
            Kind::Warning => AMBER,
            Kind::Error => RED,
        }
    }
    /// Every notification disappears by itself after three seconds.
    fn life(self) -> Duration {
        Duration::from_secs(3)
    }
}

struct Toast {
    kind: Kind,
    title: String,
    text: String,
    born: Instant,
}

#[derive(Clone, Copy, PartialEq)]
enum Screen {
    Home,
    Crypto,
    Stego,
}

#[derive(Clone, Copy, PartialEq)]
enum Tone {
    Neutral,
    Green,
    Blue,
    Amber,
    Violet,
}

impl Tone {
    fn color(self) -> Color32 {
        match self {
            Tone::Neutral => NEUTRAL,
            Tone::Green => GREEN,
            Tone::Blue => BLUE,
            Tone::Amber => AMBER,
            Tone::Violet => VIOLET,
        }
    }
    fn text(self) -> Color32 {
        match self {
            Tone::Amber => Color32::from_rgb(20, 20, 22),
            Tone::Neutral => Color32::from_rgb(220, 220, 226),
            _ => Color32::WHITE,
        }
    }
}

struct App {
    screen: Screen,
    toasts: Vec<Toast>,
    working: Option<String>,
    info: String,
    busy: bool,
    progress: Arc<Progress>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    logo: Option<egui::TextureHandle>,
    // Encryption
    c_file: String,
    c_pw: String,
    c_pw2: String,
    c_show: bool,
    // Steganography tab (false = hide, true = extract)
    s_extract: bool,
    // Hide
    h_secret: String,
    h_cover: String,
    h_out: String,
    h_out_auto: bool,
    h_pixels: bool,
    h_protect: bool,
    h_pw: String,
    h_pw2: String,
    h_show: bool,
    // Extract
    x_image: String,
    x_dir: String,
    x_pw: String,
    x_show: bool,
}

fn logo_rgba() -> Option<(Vec<u8>, u32, u32)> {
    let img = image::load_from_memory(LOGO_PNG).ok()?.to_rgba8();
    let (w, h) = img.dimensions();
    Some((img.into_raw(), w, h))
}

pub fn run() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Crypton")
        .with_inner_size([560.0, 800.0])
        .with_resizable(false)
        .with_maximize_button(false);
    if let Some((rgba, width, height)) = logo_rgba() {
        viewport = viewport.with_icon(Arc::new(egui::IconData { rgba, width, height }));
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "Crypton",
        options,
        Box::new(|cc| {
            style(&cc.egui_ctx);
            Ok(Box::new(App::new(&cc.egui_ctx)))
        }),
    )
}

fn style(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = CARD;
    v.extreme_bg_color = INPUT_BG;
    v.widgets.noninteractive.fg_stroke.color = TEXT;
    v.widgets.inactive.fg_stroke.color = TEXT;
    v.widgets.hovered.fg_stroke.color = Color32::WHITE;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(76, 76, 86));
    v.selection.bg_fill = Color32::from_rgb(70, 70, 82);
    v.selection.stroke = Stroke::new(1.5, Color32::from_rgb(210, 210, 220));
    let r = CornerRadius::same(10);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.corner_radius = r;
    v.widgets.open.corner_radius = r;
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.set_visuals_of(egui::Theme::Dark, v);
    ctx.style_mut_of(egui::Theme::Dark, |s| {
        s.spacing.item_spacing = egui::vec2(10.0, 9.0);
        s.spacing.interact_size.y = 36.0;
    });
}

// ---------------------------------------------------------------- widgets

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(14)
        .inner_margin(18)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
}

/// Numbered step header: a white badge with the step number, a title and an optional hint.
fn step(ui: &mut egui::Ui, n: u32, title: &str, hint: &str) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(vec2(26.0, 26.0), Sense::hover());
        let p = ui.painter();
        p.circle_filled(r.center(), 13.0, Color32::from_rgb(236, 236, 241));
        p.text(r.center(), Align2::CENTER_CENTER, n.to_string(), FontId::proportional(14.0), BG);
        ui.label(RichText::new(title).size(16.5).strong().color(Color32::WHITE));
        if !hint.is_empty() {
            ui.label(RichText::new(hint).size(12.5).color(MUTED));
        }
    });
    ui.add_space(2.0);
}

fn divider(ui: &mut egui::Ui) {
    ui.add_space(4.0);
    ui.separator();
    ui.add_space(4.0);
}

fn field_label(ui: &mut egui::Ui, t: &str) {
    if !t.is_empty() {
        ui.label(RichText::new(t).size(12.0).color(MUTED));
    }
}

/// Flat colored button with hover and pressed feedback.
fn button(ui: &mut egui::Ui, size: Vec2, text: &str, tone: Tone) -> egui::Response {
    let enabled = ui.is_enabled();
    let (rect, resp) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    let base = tone.color();
    let fill = if !enabled {
        base.gamma_multiply(0.4)
    } else if resp.is_pointer_button_down_on() {
        base.lerp_to_gamma(Color32::BLACK, 0.18)
    } else if resp.hovered() {
        base.lerp_to_gamma(Color32::WHITE, 0.14)
    } else {
        base
    };
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(10), fill);
    if tone == Tone::Neutral {
        p.rect_stroke(rect, CornerRadius::same(10), Stroke::new(1.0, Color32::from_rgb(62, 62, 70)), StrokeKind::Inside);
    }
    let tc = if enabled { tone.text() } else { tone.text().gamma_multiply(0.5) };
    p.text(rect.center(), Align2::CENTER_CENTER, text, FontId::proportional(15.0), tc);
    if enabled {
        resp.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        resp
    }
}

/// Segmented tab button: filled with its own color when selected.
fn tab(ui: &mut egui::Ui, size: Vec2, text: &str, selected: bool, tone: Tone) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let base = tone.color();
    let fill = if selected {
        base
    } else if resp.hovered() {
        Color32::from_rgb(54, 54, 62)
    } else {
        Color32::from_rgb(30, 30, 35)
    };
    let tc = if selected { tone.text() } else { MUTED };
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(12), fill);
    if !selected {
        p.rect_stroke(rect, CornerRadius::same(12), Stroke::new(1.0, BORDER), StrokeKind::Inside);
    }
    p.text(rect.center(), Align2::CENTER_CENTER, text, FontId::proportional(16.0), tc);
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// Path field with a "Browse" button. Returns true when "Browse" is pressed.
fn path_row(ui: &mut egui::Ui, label: &str, text: &mut String, hint: &str) -> bool {
    field_label(ui, label);
    let mut clicked = false;
    ui.horizontal(|ui| {
        let bw = 92.0;
        let tw = (ui.available_width() - bw - ui.spacing().item_spacing.x).max(60.0);
        ui.add_sized([tw, 38.0], egui::TextEdit::singleline(text).hint_text(hint).align(Align2::LEFT_CENTER));
        clicked = button(ui, vec2(bw, 38.0), "Browse", Tone::Neutral).clicked();
    });
    clicked
}

/// Password field (with "Show") and, if requested, the confirmation field.
fn password_block(ui: &mut egui::Ui, label: &str, pw: &mut String, confirm: Option<&mut String>, show: &mut bool) {
    field_label(ui, label);
    ui.horizontal(|ui| {
        let bw = 92.0;
        let tw = (ui.available_width() - bw - ui.spacing().item_spacing.x).max(60.0);
        ui.add_sized(
            [tw, 38.0],
            egui::TextEdit::singleline(pw).password(!*show).hint_text("Password").align(Align2::LEFT_CENTER),
        );
        let t = if *show { "Hide" } else { "Show" };
        if button(ui, vec2(bw, 38.0), t, Tone::Neutral).clicked() {
            *show = !*show;
        }
    });
    if let Some(c) = confirm {
        ui.add_sized(
            [ui.available_width(), 38.0],
            egui::TextEdit::singleline(c).password(!*show).hint_text("Confirm password").align(Align2::LEFT_CENTER),
        );
    }
}

/// Password and confirmation side by side, plus the "Show" button, on a single row.
fn password_pair(ui: &mut egui::Ui, pw: &mut String, confirm: &mut String, show: &mut bool) {
    ui.horizontal(|ui| {
        let bw = 92.0;
        let gap = ui.spacing().item_spacing.x;
        let tw = ((ui.available_width() - bw - 2.0 * gap) / 2.0).max(50.0);
        ui.add_sized(
            [tw, 38.0],
            egui::TextEdit::singleline(pw).password(!*show).hint_text("Password").align(Align2::LEFT_CENTER),
        );
        ui.add_sized(
            [tw, 38.0],
            egui::TextEdit::singleline(confirm).password(!*show).hint_text("Confirm").align(Align2::LEFT_CENTER),
        );
        let t = if *show { "Hide" } else { "Show" };
        if button(ui, vec2(bw, 38.0), t, Tone::Neutral).clicked() {
            *show = !*show;
        }
    });
}

#[derive(Clone, Copy)]
enum Icon {
    Lock,
    Image,
}

fn draw_icon(p: &egui::Painter, rect: Rect, icon: Icon, color: Color32, hole: Color32) {
    let c = rect.center();
    let s = rect.width();
    match icon {
        Icon::Lock => {
            let body = Rect::from_center_size(c + vec2(0.0, s * 0.09), vec2(s * 0.50, s * 0.38));
            let r = s * 0.15;
            let mut pts = vec![pos2(c.x - r, body.top() + 2.0)];
            for i in 0..=18 {
                let a = PI * i as f32 / 18.0;
                pts.push(pos2(c.x - r * a.cos(), body.top() - r * a.sin() + 1.0));
            }
            pts.push(pos2(c.x + r, body.top() + 2.0));
            p.add(Shape::line(pts, Stroke::new(3.5, color)));
            p.rect_filled(body, CornerRadius::same(5), color);
            p.circle_filled(body.center() - vec2(0.0, s * 0.02), s * 0.05, hole);
            p.rect_filled(
                Rect::from_center_size(body.center() + vec2(0.0, s * 0.07), vec2(s * 0.035, s * 0.10)),
                CornerRadius::same(1),
                hole,
            );
        }
        Icon::Image => {
            let frame = Rect::from_center_size(c - vec2(s * 0.03, s * 0.02), vec2(s * 0.58, s * 0.46));
            p.rect_stroke(frame, CornerRadius::same(6), Stroke::new(2.5, color), StrokeKind::Inside);
            p.circle_filled(frame.left_top() + vec2(s * 0.14, s * 0.12), s * 0.05, color);
            p.add(Shape::convex_polygon(
                vec![
                    pos2(frame.left() + 3.0, frame.bottom() - 3.0),
                    pos2(frame.left() + s * 0.20, frame.bottom() - s * 0.20),
                    pos2(frame.left() + s * 0.32, frame.bottom() - 3.0),
                ],
                color,
                Stroke::NONE,
            ));
            p.add(Shape::convex_polygon(
                vec![
                    pos2(frame.left() + s * 0.22, frame.bottom() - 3.0),
                    pos2(frame.left() + s * 0.36, frame.bottom() - s * 0.27),
                    pos2(frame.right() - 3.0, frame.bottom() - 3.0),
                ],
                color.gamma_multiply(0.7),
                Stroke::NONE,
            ));
            let px = s * 0.085;
            for (dx, dy, a) in [(0.0, 0.0, 1.0), (px * 1.35, px * 1.35, 0.7), (px * 1.35, 0.0, 0.45), (0.0, px * 1.35, 0.45)] {
                let o = pos2(frame.right() - px * 0.4 + dx, frame.bottom() - px * 0.4 + dy);
                p.rect_filled(Rect::from_min_size(o, vec2(px, px)), CornerRadius::same(2), color.gamma_multiply(a));
            }
        }
    }
}

/// Wide clickable card of the start screen.
fn home_card(ui: &mut egui::Ui, title: &str, desc: &str, tone: Tone, icon: Icon) -> egui::Response {
    let width = ui.available_width().min(480.0);
    let (rect, resp) = ui.allocate_exact_size(vec2(width, 112.0), Sense::click());
    let hovered = resp.hovered();
    let accent = tone.color();
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(18), if hovered { CARD_HOVER } else { CARD });
    p.rect_stroke(
        rect,
        CornerRadius::same(18),
        Stroke::new(if hovered { 2.0 } else { 1.0 }, if hovered { accent } else { BORDER }),
        StrokeKind::Inside,
    );
    let ib = Rect::from_min_size(rect.min + vec2(22.0, 25.0), vec2(62.0, 62.0));
    p.rect_filled(ib, CornerRadius::same(16), accent.gamma_multiply(0.16));
    p.rect_stroke(ib, CornerRadius::same(16), Stroke::new(1.0, accent.gamma_multiply(0.55)), StrokeKind::Inside);
    draw_icon(p, ib, icon, accent, Color32::from_rgb(30, 30, 40));
    p.text(rect.min + vec2(106.0, 26.0), Align2::LEFT_TOP, title, FontId::proportional(22.0), Color32::WHITE);
    let galley = p.layout(desc.to_string(), FontId::proportional(14.0), MUTED, rect.width() - 128.0);
    p.galley(rect.min + vec2(106.0, 58.0), galley, MUTED);
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// One notification card. Returns true when its close button is pressed.
fn toast_frame(ui: &mut egui::Ui, accent: Color32, title: &str, text: &str, progress: Option<f32>, closable: bool, alpha: f32) -> bool {
    let mut closed = false;
    egui::Frame::new()
        .fill(CARD_HOVER.gamma_multiply(alpha))
        .stroke(Stroke::new(1.5, accent.gamma_multiply(alpha)))
        .corner_radius(12)
        .inner_margin(14)
        .shadow(egui::epaint::Shadow { offset: [0, 4], blur: 18, spread: 0, color: Color32::from_black_alpha((170.0 * alpha) as u8) })
        .show(ui, |ui| {
            ui.set_opacity(alpha);
            ui.set_width(300.0);
            ui.horizontal_top(|ui| {
                let (r, _) = ui.allocate_exact_size(vec2(12.0, 20.0), Sense::hover());
                ui.painter().circle_filled(r.center(), 5.0, accent);
                ui.vertical(|ui| {
                    ui.set_width(232.0);
                    if !title.is_empty() {
                        ui.label(RichText::new(title).strong().color(accent));
                    }
                    ui.add(egui::Label::new(RichText::new(text).color(TEXT)).wrap());
                    if let Some(f) = progress {
                        ui.add(egui::ProgressBar::new(f).fill(BLUE).desired_width(f32::INFINITY));
                    }
                });
                if closable {
                    let (r, resp) = ui.allocate_exact_size(vec2(24.0, 24.0), Sense::click());
                    let c = if resp.hovered() { Color32::WHITE } else { MUTED };
                    let st = Stroke::new(1.6, c);
                    let m = r.center();
                    ui.painter().line_segment([m + vec2(-5.0, -5.0), m + vec2(5.0, 5.0)], st);
                    ui.painter().line_segment([m + vec2(-5.0, 5.0), m + vec2(5.0, -5.0)], st);
                    if resp.on_hover_cursor(CursorIcon::PointingHand).clicked() {
                        closed = true;
                    }
                }
            });
        });
    closed
}

/// "1.4 s" / "230 ms": how long an operation took.
fn took(t0: Instant) -> String {
    let d = t0.elapsed();
    if d.as_secs() >= 1 {
        format!("{:.1} s", d.as_secs_f32())
    } else {
        format!("{} ms", d.as_millis())
    }
}

fn pw_bytes(s: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.as_bytes().to_vec())
}

fn opt_pw(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    if s.is_empty() { None } else { Some(pw_bytes(s)) }
}

fn file_name(p: &Path) -> String {
    p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn stem(p: &Path) -> String {
    p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "image".into())
}

fn images_dialog() -> rfd::FileDialog {
    rfd::FileDialog::new().add_filter("Images", &["png", "jpg", "jpeg", "bmp"])
}

// ---------------------------------------------------------------- application

impl App {
    fn new(ctx: &egui::Context) -> Self {
        let (tx, rx) = channel();
        let logo = logo_rgba().map(|(rgba, w, h)| {
            ctx.load_texture(
                "logo",
                egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba),
                egui::TextureOptions::LINEAR,
            )
        });
        Self {
            logo,
            screen: Screen::Home,
            toasts: Vec::new(),
            working: None,
            info: String::new(),
            busy: false,
            progress: Arc::new(Progress::new()),
            tx,
            rx,
            c_file: String::new(),
            c_pw: String::new(),
            c_pw2: String::new(),
            c_show: false,
            s_extract: false,
            h_secret: String::new(),
            h_cover: String::new(),
            h_out: String::new(),
            h_out_auto: true,
            h_pixels: true,
            h_protect: true,
            h_pw: String::new(),
            h_pw2: String::new(),
            h_show: false,
            x_image: String::new(),
            x_dir: String::new(),
            x_pw: String::new(),
            x_show: false,
        }
    }

    /// Pushes a notification (an identical one is replaced; at most four are kept).
    fn notify(&mut self, kind: Kind, title: &str, text: impl Into<String>) {
        let text = text.into();
        self.toasts.retain(|t| !(t.title == title && t.text == text));
        self.toasts.push(Toast { kind, title: title.to_string(), text, born: Instant::now() });
        while self.toasts.len() > 4 {
            self.toasts.remove(0);
        }
    }

    fn fail(&mut self, text: &str) {
        self.notify(Kind::Error, "Error", text);
    }

    /// Confirms that a file or folder was chosen with "Browse".
    fn picked(&mut self, title: &str, p: &Path) {
        let name = file_name(p);
        let shown = if name.is_empty() { p.display().to_string() } else { name };
        self.notify(Kind::Info, title, shown);
    }

    fn weak_password_warning(&mut self, pw: &str) {
        if pw.chars().count() < 8 {
            self.notify(Kind::Warning, "Weak password", "Use at least 12 characters for stronger protection.");
        }
    }

    fn existing_file(&mut self, text: &str, what: &str) -> Option<PathBuf> {
        let t = text.trim();
        if t.is_empty() {
            self.fail(&format!("{what}: choose a file."));
            return None;
        }
        let p = PathBuf::from(t);
        if !p.is_file() {
            self.fail(&format!("{what}: the file does not exist."));
            return None;
        }
        Some(p)
    }

    /// Runs a job on a separate thread so the window never freezes.
    fn spawn<F>(&mut self, ctx: &egui::Context, label: &str, f: F)
    where
        F: FnOnce(&Progress) -> Msg + Send + 'static,
    {
        self.busy = true;
        self.info.clear();
        self.working = Some(label.to_string());
        self.progress = Arc::new(Progress::new());
        let p = self.progress.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let m = catch_unwind(AssertUnwindSafe(|| f(&p)))
                .unwrap_or_else(|_| Msg::Failed(E::Message("Unexpected internal error.".into())));
            let _ = tx.send(m);
            ctx.request_repaint();
        });
    }

    fn open(&mut self, screen: Screen) {
        self.screen = screen;
        self.toasts.clear();
        self.info.clear();
    }

    // ------------------------------------------------------------ encryption

    fn encrypt(&mut self, ctx: &egui::Context) {
        let Some(input) = self.existing_file(&self.c_file.clone(), "File to encrypt") else { return };
        if self.c_pw.is_empty() {
            return self.fail("Enter a password.");
        }
        if self.c_pw != self.c_pw2 {
            return self.fail("The two passwords do not match.");
        }
        let weak = self.c_pw.clone();
        self.weak_password_warning(&weak);
        let mut dlg = rfd::FileDialog::new()
            .set_title("Save the encrypted file")
            .set_file_name(format!("{}.{}", file_name(&input), crate::crypto::EXTENSION))
            .add_filter("Crypton file", &[crate::crypto::EXTENSION]);
        if let Some(d) = input.parent() {
            dlg = dlg.set_directory(d);
        }
        let Some(output) = dlg.save_file() else {
            return self.notify(Kind::Warning, "Encryption cancelled", "No file was written.");
        };
        let pw = pw_bytes(&self.c_pw);
        self.notify(Kind::Info, "Encryption started", file_name(&input));
        self.spawn(ctx, "Encrypting…", move |p| {
            let t0 = Instant::now();
            match ops::encrypt_file(&input, &output, &pw, p) {
                Ok(()) => Msg::Success {
                    title: "File encrypted".into(),
                    text: format!("Saved to: {}\nDone in {}.", output.display(), took(t0)),
                },
                Err(e) => Msg::Failed(e),
            }
        });
    }

    fn decrypt(&mut self, ctx: &egui::Context) {
        let Some(input) = self.existing_file(&self.c_file.clone(), "File to decrypt") else { return };
        if self.c_pw.is_empty() {
            return self.fail("Enter the password.");
        }
        let pw = pw_bytes(&self.c_pw);
        self.notify(Kind::Info, "Decryption started", file_name(&input));
        self.spawn(ctx, "Verifying the file…", move |p| match ops::prepare_decrypt(&input, &pw, p) {
            Ok(prep) => Msg::DecryptReady(prep),
            Err(e) => Msg::Failed(e),
        });
    }

    fn verify(&mut self, ctx: &egui::Context) {
        let Some(input) = self.existing_file(&self.c_file.clone(), "File to check") else { return };
        let pw = opt_pw(&self.c_pw);
        let title = if pw.is_some() { "Integrity verified" } else { "Structure is valid" };
        self.notify(Kind::Info, "Verification started", file_name(&input));
        self.spawn(ctx, "Checking integrity…", move |p| {
            let t0 = Instant::now();
            match ops::verify_file(&input, pw.as_ref().map(|z| z.as_slice()), p) {
                Ok(t) => Msg::Success { title: title.into(), text: format!("{t}\nDone in {}.", took(t0)) },
                Err(e) => Msg::Failed(e),
            }
        });
    }

    fn info(&mut self, ctx: &egui::Context) {
        let Some(input) = self.existing_file(&self.c_file.clone(), "File to inspect") else { return };
        let pw = opt_pw(&self.c_pw);
        self.spawn(ctx, "Reading information…", move |_| {
            Msg::Info(ops::info_file(&input, pw.as_ref().map(|z| z.as_slice())))
        });
    }

    // ------------------------------------------------------------ steganography

    /// Suggests the output file name until the user picks their own.
    fn suggest_out(&mut self) {
        if self.h_cover.trim().is_empty() || !(self.h_out.is_empty() || self.h_out_auto) {
            return;
        }
        let cover = PathBuf::from(self.h_cover.trim());
        let ext = if self.h_pixels {
            "png".to_string()
        } else {
            cover.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_else(|| "png".into())
        };
        let name = format!("{}_hidden.{ext}", stem(&cover));
        let path = match cover.parent() {
            Some(d) => d.join(name),
            None => PathBuf::from(name),
        };
        self.h_out = path.to_string_lossy().into_owned();
        self.h_out_auto = true;
    }

    fn hide(&mut self, ctx: &egui::Context) {
        let Some(secret) = self.existing_file(&self.h_secret.clone(), "File to hide") else { return };
        let Some(image) = self.existing_file(&self.h_cover.clone(), "Cover image") else { return };
        if self.h_out.trim().is_empty() {
            return self.fail("Choose where to save the image with the hidden file.");
        }
        let mut out = PathBuf::from(self.h_out.trim());
        if out.extension().is_none() {
            let ext = if self.h_pixels {
                "png".to_string()
            } else {
                image.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_else(|| "png".into())
            };
            out.set_extension(ext);
        }
        let password = if self.h_protect {
            if self.h_pw.is_empty() {
                return self.fail("Enter a password to protect the hidden file.");
            }
            if self.h_pw != self.h_pw2 {
                return self.fail("The two passwords do not match.");
            }
            let weak = self.h_pw.clone();
            self.weak_password_warning(&weak);
            Some(pw_bytes(&self.h_pw))
        } else {
            self.notify(Kind::Warning, "Not protected", "Anyone who has this image will be able to extract the hidden file.");
            None
        };
        let pixels = self.h_pixels;
        self.notify(Kind::Info, "Hiding started", file_name(&secret));
        self.spawn(ctx, "Hiding the file…", move |_| {
            let t0 = Instant::now();
            let pw = password.as_ref().map(|z| z.as_slice());
            let r = if pixels { stego::hide_pixels(&secret, &image, &out, pw) } else { stego::hide_tail(&secret, &image, &out, pw) };
            match r {
                Ok(path) => Msg::Success {
                    title: "File hidden".into(),
                    text: format!("Image saved to: {}\nDone in {}.", path.display(), took(t0)),
                },
                Err(e) => Msg::Failed(e),
            }
        });
    }

    fn extract(&mut self, ctx: &egui::Context) {
        let Some(image) = self.existing_file(&self.x_image.clone(), "Image") else { return };
        if self.x_dir.trim().is_empty() || !Path::new(self.x_dir.trim()).is_dir() {
            return self.fail("The destination folder does not exist: choose it with \"Browse\".");
        }
        let pw = opt_pw(&self.x_pw);
        self.notify(Kind::Info, "Extraction started", file_name(&image));
        self.spawn(ctx, "Looking for hidden content…", move |_| {
            match stego::extract_to_memory(&image, pw.as_ref().map(|z| z.as_slice())) {
                Ok(ex) => Msg::ExtractReady(ex),
                Err(e) => Msg::Failed(e),
            }
        });
    }

    // ------------------------------------------------------------ messages from worker threads

    fn handle(&mut self, ctx: &egui::Context, m: Msg) {
        self.working = None;
        self.busy = false;
        match m {
            Msg::Success { title, text } => self.notify(Kind::Success, &title, text),
            Msg::Failed(e) => self.notify(Kind::Error, "Error", e.to_string()),
            Msg::Info(Ok(t)) => {
                self.info = t;
                self.notify(Kind::Info, "Information loaded", "The details of the file are shown below.");
            }
            Msg::Info(Err(e)) => {
                self.info.clear();
                self.notify(Kind::Error, "Error", e.to_string());
            }
            Msg::DecryptReady(prep) => {
                self.notify(Kind::Success, "Integrity verified", "The password is correct and all data is authentic.");
                let mut dlg = rfd::FileDialog::new()
                    .set_title("Save the decrypted file")
                    .set_file_name(prep.suggested_name.clone());
                if let Some(d) = prep.input.parent() {
                    dlg = dlg.set_directory(d);
                }
                match dlg.save_file() {
                    Some(out) => {
                        self.spawn(ctx, "Writing the decrypted file…", move |p| {
                            let t0 = Instant::now();
                            match ops::finish_decrypt(&prep, &out, p) {
                                Ok(()) => Msg::Success {
                                    title: "File decrypted".into(),
                                    text: format!("Saved to: {}\nDone in {}.", out.display(), took(t0)),
                                },
                                Err(e) => Msg::Failed(e),
                            }
                        });
                    }
                    None => self.notify(Kind::Warning, "Decryption cancelled", "Nothing was written to disk."),
                }
            }
            Msg::ExtractReady(ex) => {
                let dir = PathBuf::from(self.x_dir.trim());
                let how = ex.method.label();
                self.notify(Kind::Info, "Hidden content found", format!("Method: {how}."));
                self.spawn(ctx, "Writing the extracted file…", move |_| match stego::write_extracted(&ex, &dir) {
                    Ok(p) => Msg::Success { title: "File extracted".into(), text: format!("Saved to: {}", p.display()) },
                    Err(e) => Msg::Failed(e),
                });
            }
        }
    }

    // ------------------------------------------------------------ screens

    fn logo_image(&self, ui: &mut egui::Ui, size: f32) {
        if let Some(t) = &self.logo {
            ui.image((t.id(), vec2(size, size)));
        }
    }

    fn home(&mut self, ui: &mut egui::Ui) {
        let h = ui.available_height();
        ui.vertical_centered(|ui| {
            ui.add_space(((h - 520.0) / 2.0).max(12.0));
            self.logo_image(ui, 112.0);
            ui.add_space(4.0);
            ui.label(RichText::new("Crypton").size(42.0).strong().color(Color32::WHITE));
            ui.label(RichText::new("Encrypt your files and hide them inside images.").size(15.0).color(MUTED));
            ui.add_space(26.0);
            if home_card(ui, "Encryption", "Encrypt, decrypt and verify any file with a password.", Tone::Blue, Icon::Lock).clicked() {
                self.open(Screen::Crypto);
            }
            ui.add_space(6.0);
            if home_card(ui, "Steganography", "Hide a file inside an image, or extract one from it.", Tone::Violet, Icon::Image).clicked() {
                self.open(Screen::Stego);
            }
            ui.add_space(20.0);
            ui.label(RichText::new("AES-256 + ChaCha20  •  Argon2id  •  Open source (MIT)").size(12.0).color(MUTED));
        });
    }

    /// Section header: "Back" on the left; on the right the logo first, then the text,
    /// all on one row whose height is the logo's (the text is never taller than the logo).
    fn header(&mut self, ui: &mut egui::Ui, title: &str, subtitle: &str) {
        const LOGO: f32 = 54.0;
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), LOGO),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.add_enabled_ui(!self.busy, |ui| {
                    if button(ui, vec2(84.0, 38.0), "Back", Tone::Neutral).clicked() {
                        self.open(Screen::Home);
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.logo_image(ui, LOGO);
                    ui.with_layout(egui::Layout::top_down(egui::Align::Max), |ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.label(RichText::new(title).size(22.0).strong().color(Color32::WHITE));
                        ui.label(RichText::new(subtitle).size(12.0).color(MUTED));
                    });
                });
            },
        );
        ui.add_space(8.0);
    }

    /// Notifications in the top-right corner: progress of the running job, then the queue.
    fn toasts_ui(&mut self, ctx: &egui::Context) {
        self.toasts.retain(|t| t.born.elapsed() < t.kind.life());
        if self.working.is_none() && self.toasts.is_empty() {
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(100));
        let mut close: Option<usize> = None;
        let working = self.working.clone();
        let fraction = self.progress.fraction();
        egui::Area::new(egui::Id::unique("toasts"))
            .anchor(Align2::RIGHT_TOP, vec2(-16.0, 86.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing.y = 8.0;
                if let Some(label) = &working {
                    toast_frame(ui, VIOLET, "", label, Some(fraction), false, 1.0);
                }
                for (i, t) in self.toasts.iter().enumerate() {
                    let left = t.kind.life().saturating_sub(t.born.elapsed()).as_secs_f32();
                    let alpha = (left / 0.4).clamp(0.0, 1.0);
                    if toast_frame(ui, t.kind.color(), &t.title, &t.text, None, true, alpha) {
                        close = Some(i);
                    }
                }
            });
        if let Some(i) = close {
            self.toasts.remove(i);
        }
    }

    fn crypto_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.header(ui, "Encryption", "AES-256-GCM + ChaCha20-Poly1305 + Argon2id");
        card(ui, |ui| {
            ui.add_enabled_ui(!self.busy, |ui| {
                step(ui, 1, "Choose a file", "");
                if path_row(ui, "", &mut self.c_file, "Choose a file or paste its path") {
                    if let Some(p) = rfd::FileDialog::new().set_title("Choose the file").pick_file() {
                        self.c_file = p.to_string_lossy().into_owned();
                        self.picked("File selected", &p);
                    }
                }
                divider(ui);
                step(ui, 2, "Set the password", "type it twice to encrypt");
                password_block(ui, "", &mut self.c_pw, Some(&mut self.c_pw2), &mut self.c_show);
                ui.label(RichText::new("A forgotten password cannot be recovered.").size(12.0).color(MUTED));
                divider(ui);
                step(ui, 3, "Pick an action", "");
                let w = (ui.available_width() - 3.0 * ui.spacing().item_spacing.x) / 4.0;
                ui.horizontal(|ui| {
                    if button(ui, vec2(w, 46.0), "Encrypt", Tone::Green).clicked() {
                        self.encrypt(ctx);
                    }
                    if button(ui, vec2(w, 46.0), "Decrypt", Tone::Blue).clicked() {
                        self.decrypt(ctx);
                    }
                    if button(ui, vec2(w, 46.0), "Verify", Tone::Amber).clicked() {
                        self.verify(ctx);
                    }
                    if button(ui, vec2(w, 46.0), "Info", Tone::Violet).clicked() {
                        self.info(ctx);
                    }
                });
            });
        });
        if !self.info.is_empty() {
            card(ui, |ui| {
                field_label(ui, "File information");
                let mut shown = self.info.clone();
                ui.add(
                    egui::TextEdit::multiline(&mut shown)
                        .desired_rows(5)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
            });
        }
    }

    fn stego_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.header(ui, "Steganography", "Hide files inside images, or extract them");
        ui.add_enabled_ui(!self.busy, |ui| {
            ui.horizontal(|ui| {
                let w = (ui.available_width() - ui.spacing().item_spacing.x) / 2.0;
                if tab(ui, vec2(w, 44.0), "Hide a file", !self.s_extract, Tone::Green).clicked() {
                    self.s_extract = false;
                }
                if tab(ui, vec2(w, 44.0), "Extract a file", self.s_extract, Tone::Blue).clicked() {
                    self.s_extract = true;
                }
            });
        });
        if !self.s_extract {
            card(ui, |ui| {
                ui.add_enabled_ui(!self.busy, |ui| {
                    step(ui, 1, "Select the files", "");
                    if path_row(ui, "File to hide", &mut self.h_secret, "Choose the file") {
                        if let Some(p) = rfd::FileDialog::new().set_title("File to hide").pick_file() {
                            self.h_secret = p.to_string_lossy().into_owned();
                            self.picked("File to hide selected", &p);
                        }
                    }
                    if path_row(ui, "Cover image", &mut self.h_cover, "PNG, JPG or BMP") {
                        if let Some(p) = images_dialog().set_title("Cover image").pick_file() {
                            self.h_cover = p.to_string_lossy().into_owned();
                            self.picked("Cover image selected", &p);
                            self.suggest_out();
                        }
                    }
                    if path_row(ui, "Save as", &mut self.h_out, "Where to save the result") {
                        let mut dlg = rfd::FileDialog::new().set_title("Save the image with the hidden file");
                        if self.h_pixels {
                            dlg = dlg.add_filter("Lossless image", &["png", "bmp"]);
                        }
                        if let Some(p) = dlg.save_file() {
                            self.h_out = p.to_string_lossy().into_owned();
                            self.h_out_auto = false;
                            self.picked("Save location set", &p);
                        }
                    }
                    divider(ui);
                    step(ui, 2, "Choose the method", "");
                    ui.horizontal(|ui| {
                        let before = self.h_pixels;
                        ui.radio_value(&mut self.h_pixels, true, "Pixel (LSB)")
                            .on_hover_text("Barely visible. The result is saved as PNG or BMP only.");
                        ui.radio_value(&mut self.h_pixels, false, "Appended to file")
                            .on_hover_text("Pixels untouched. Lost if the image is re-encoded (social networks, messaging apps).");
                        if before != self.h_pixels {
                            self.suggest_out();
                        }
                    });
                    divider(ui);
                    step(ui, 3, "Protect it", "optional");
                    ui.checkbox(&mut self.h_protect, "Password-protect (also encrypts the name)");
                    if self.h_protect {
                        password_pair(ui, &mut self.h_pw, &mut self.h_pw2, &mut self.h_show);
                    }
                    ui.add_space(8.0);
                    if button(ui, vec2(ui.available_width(), 46.0), "Hide file", Tone::Green).clicked() {
                        self.hide(ctx);
                    }
                });
            });
        } else {
            card(ui, |ui| {
                ui.add_enabled_ui(!self.busy, |ui| {
                    step(ui, 1, "Select the image", "method auto-detected");
                    if path_row(ui, "", &mut self.x_image, "Image with the hidden file") {
                        let d = images_dialog().set_title("Image with the hidden file").pick_file();
                        if let Some(p) = d {
                            if self.x_dir.trim().is_empty() {
                                if let Some(par) = p.parent() {
                                    self.x_dir = par.to_string_lossy().into_owned();
                                }
                            }
                            self.x_image = p.to_string_lossy().into_owned();
                            self.picked("Image selected", &p);
                        }
                    }
                    divider(ui);
                    step(ui, 2, "Choose the destination", "");
                    if path_row(ui, "", &mut self.x_dir, "Folder for the extracted file") {
                        if let Some(p) = rfd::FileDialog::new().set_title("Destination folder").pick_folder() {
                            self.x_dir = p.to_string_lossy().into_owned();
                            self.picked("Destination folder set", &p);
                        }
                    }
                    divider(ui);
                    step(ui, 3, "Enter the password", "only if protected");
                    password_block(ui, "", &mut self.x_pw, None, &mut self.x_show);
                    ui.add_space(8.0);
                    if button(ui, vec2(ui.available_width(), 46.0), "Extract file", Tone::Blue).clicked() {
                        self.extract(ctx);
                    }
                });
            });
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        while let Ok(m) = self.rx.try_recv() {
            self.handle(&ctx, m);
        }
        if self.busy {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).inner_margin(16)).show(ui, |ui| {
            if self.screen == Screen::Home {
                self.home(ui);
                return;
            }
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                // Central column: narrow for encryption, wider for steganography.
                let w = (ui.available_width() - 4.0).min(MAX_W);
                ui.vertical_centered(|ui| {
                    ui.allocate_ui_with_layout(egui::vec2(w, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.set_width(w);
                        match self.screen {
                            Screen::Crypto => self.crypto_screen(ui, &ctx),
                            Screen::Stego => self.stego_screen(ui, &ctx),
                            Screen::Home => {}
                        }
                    });
                });
            });
        });
        self.toasts_ui(&ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        for s in [&mut self.c_pw, &mut self.c_pw2, &mut self.h_pw, &mut self.h_pw2, &mut self.x_pw, &mut self.info] {
            s.zeroize();
        }
    }
}
