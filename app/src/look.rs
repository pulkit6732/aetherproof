//! AetherProof's own look: a ledger. Ink rail, paper ground, a serif for figures and titles,
//! tabular numerals, verdicts as ink stamps. One deliberate light identity, not a theme toggle.

use rune::tok::Family;
use rune::{Align, Color, El, TextStyle, el, text};
use rune_kit::{Kit, PaletteSeed};
use std::sync::OnceLock;

pub struct Look {
    pub paper: Color,
    pub card: Color,
    pub rule: Color,
    pub ink: Color,
    pub ink2: Color,
    pub faint: Color,
    pub rail: Color,
    pub rail_hi: Color,
    pub rail_text: Color,
    pub navy: Color,
    pub brass: Color,
    pub crimson: Color,
    pub sage: Color,
    pub amber: Color,
}

fn hex(c: &str) -> Color {
    rune::color::hex(c).expect("valid hex colour")
}

pub fn look() -> &'static Look {
    static L: OnceLock<Look> = OnceLock::new();
    L.get_or_init(|| Look {
        paper: hex("#f4efe5"),
        card: hex("#fbf8f2"),
        rule: hex("#ddd4c3"),
        ink: hex("#1b2230"),
        ink2: hex("#4b5263"),
        faint: hex("#8b8f97"),
        rail: hex("#161d2b"),
        rail_hi: hex("#26304a"),
        rail_text: hex("#e9e3d6"),
        navy: hex("#1f3a5f"),
        brass: hex("#9c7629"),
        crimson: hex("#a3261e"),
        sage: hex("#2f6b4f"),
        amber: hex("#94650f"),
    })
}

/// rune-kit components (inputs, buttons) on the same paper and ink.
pub fn kit() -> &'static Kit {
    static K: OnceLock<Kit> = OnceLock::new();
    K.get_or_init(|| {
        let l = look();
        Kit::from_palette(PaletteSeed { bg: l.card, fg: l.ink, accent: l.navy })
    })
}

pub const SERIF: Family = Family::Named("Instrument Serif");

pub fn display(size: f32) -> TextStyle {
    TextStyle::new(size, 400.0).family(SERIF).lh(size * 1.1)
}
pub fn body() -> TextStyle {
    TextStyle::new(14.0, 420.0).lh(21.0)
}
pub fn label() -> TextStyle {
    TextStyle::new(11.0, 650.0).tracking(1.1).lh(14.0)
}
pub fn figures(size: f32, weight: f32) -> TextStyle {
    TextStyle::new(size, weight).features("'tnum' 1").lh(size * 1.35)
}
pub fn code() -> TextStyle {
    TextStyle::new(12.5, 450.0).mono().lh(18.0)
}

/// ₹ with Indian digit grouping: 12,34,567.89
pub fn inr(minor: i64) -> String {
    let neg = minor < 0;
    let m = minor.unsigned_abs();
    let (whole, paise) = (m / 100, m % 100);
    let s = whole.to_string();
    let grouped = if s.len() <= 3 {
        s
    } else {
        let (head, tail) = s.split_at(s.len() - 3);
        let mut parts: Vec<String> = Vec::new();
        let mut h = head.to_owned();
        while h.len() > 2 {
            parts.insert(0, h.split_off(h.len() - 2));
        }
        if !h.is_empty() {
            parts.insert(0, h);
        }
        format!("{},{}", parts.join(","), tail)
    };
    format!("{}₹{}.{:02}", if neg { "-" } else { "" }, grouped, paise)
}

/// A verdict as an ink stamp.
pub fn stamp(verdict: &str) -> El {
    let l = look();
    let c = match verdict {
        "matched" | "allow" | "ok" | "intact" => l.sage,
        "ambiguous" | "pending" => l.amber,
        "missing" => l.ink2,
        _ => l.crimson,
    };
    let word = match verdict {
        "ambiguous" => "PENDING".to_owned(),
        v => v.to_uppercase(),
    };
    el().px(7.0).py(2.0).radius(3.0).border(1.4, c).fill(c.alpha(0.07))
        .child(text(word).font(label()).color(c))
}

pub fn eyebrow(t: &str) -> El {
    text(t.to_uppercase()).font(label()).color(look().brass)
}

pub fn rule() -> El {
    el().h(1.0).w_full().fill(look().rule)
}

pub fn money(minor: i64, size: f32, color: Color) -> El {
    text(inr(minor)).font(figures(size, 500.0)).color(color).align(Align::End)
}

#[cfg(test)]
mod tests {
    use super::inr;

    #[test]
    fn indian_grouping() {
        assert_eq!(inr(0), "₹0.00");
        assert_eq!(inr(4_850_000), "₹48,500.00");
        assert_eq!(inr(12_500_000), "₹1,25,000.00");
        assert_eq!(inr(123_456_789), "₹12,34,567.89");
        assert_eq!(inr(1_000_000_000_00), "₹1,00,00,00,000.00");
        assert_eq!(inr(100), "₹1.00");
    }
}
