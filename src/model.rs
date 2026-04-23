use std::borrow::Cow;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub ssid: String,
    pub channel: u16,
    pub signal_dbm: i16,
    pub security: String,
    pub band: Band,
}

impl Network {
    pub fn signal_percent(&self) -> u16 {
        dbm_to_percent(self.signal_dbm)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    Ghz24,
    Ghz5,
    Unknown,
}

impl Band {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ghz24 => "2.4 GHz",
            Self::Ghz5 => "5 GHz",
            Self::Unknown => "Other",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChannelScore {
    pub channel: u16,
    pub congestion: f32,
    pub network_count: usize,
}

#[derive(Clone, Debug)]
pub struct Recommendation {
    pub band: Band,
    pub best_channel: Option<ChannelScore>,
    pub explanation: String,
}

#[derive(Clone, Debug)]
pub struct Analysis {
    pub networks: Vec<Network>,
    pub channels_24: Vec<ChannelScore>,
    pub channels_5: Vec<ChannelScore>,
    pub recommendation_24: Recommendation,
    pub recommendation_5: Recommendation,
}

impl Analysis {
    pub fn from_networks(mut networks: Vec<Network>) -> Self {
        networks.sort_by(|left, right| {
            right
                .signal_dbm
                .cmp(&left.signal_dbm)
                .then_with(|| left.ssid.cmp(&right.ssid))
        });

        let channels_24 = score_band(&networks, Band::Ghz24, &channels_24ghz());
        let channels_5 = score_band(&networks, Band::Ghz5, &channels_5ghz());
        let recommendation_24 = recommend(Band::Ghz24, &channels_24);
        let recommendation_5 = recommend(Band::Ghz5, &channels_5);

        Self {
            networks,
            channels_24,
            channels_5,
            recommendation_24,
            recommendation_5,
        }
    }
}

pub fn infer_band(channel: u16) -> Band {
    match channel {
        1..=14 => Band::Ghz24,
        30..=196 => Band::Ghz5,
        _ => Band::Unknown,
    }
}

fn channels_24ghz() -> Vec<u16> {
    (1..=11).collect()
}

fn channels_5ghz() -> Vec<u16> {
    vec![
        36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 144, 149, 153, 157,
        161, 165,
    ]
}

fn score_band(networks: &[Network], band: Band, channels: &[u16]) -> Vec<ChannelScore> {
    let channel_set: BTreeMap<u16, (f32, usize)> = channels
        .iter()
        .map(|channel| (*channel, (0.0, 0)))
        .collect();
    let mut scores = channel_set;

    for network in networks.iter().filter(|network| network.band == band) {
        for channel in channels {
            let overlap = overlap_factor(network.channel, *channel, band);
            if overlap > 0.0 {
                let entry = scores.entry(*channel).or_insert((0.0, 0));
                entry.0 += normalized_signal(network.signal_dbm) * overlap;
                entry.1 += 1;
            }
        }
    }

    scores
        .into_iter()
        .map(|(channel, (congestion, network_count))| ChannelScore {
            channel,
            congestion,
            network_count,
        })
        .collect()
}

fn recommend(band: Band, scores: &[ChannelScore]) -> Recommendation {
    let choice = scores.iter().min_by(|left, right| {
        left.congestion
            .total_cmp(&right.congestion)
            .then_with(|| left.network_count.cmp(&right.network_count))
    });

    let explanation = match choice {
        Some(score) if score.network_count == 0 => format!(
            "Channel {} looks open with no detected competing networks.",
            score.channel
        ),
        Some(score) => format!(
            "Channel {} has the lowest estimated congestion score ({:.2}) across {} competing networks.",
            score.channel, score.congestion, score.network_count
        ),
        None => format!("No {} channels were available to score.", band.label()),
    };

    Recommendation {
        band,
        best_channel: choice.cloned(),
        explanation,
    }
}

fn overlap_factor(source_channel: u16, target_channel: u16, band: Band) -> f32 {
    match band {
        Band::Ghz24 => {
            let distance = source_channel.abs_diff(target_channel);
            match distance {
                0 => 1.0,
                1 => 0.75,
                2 => 0.45,
                3 => 0.2,
                _ => 0.0,
            }
        }
        Band::Ghz5 => {
            if source_channel == target_channel {
                1.0
            } else {
                0.0
            }
        }
        Band::Unknown => 0.0,
    }
}

fn normalized_signal(signal_dbm: i16) -> f32 {
    dbm_to_percent(signal_dbm) as f32 / 100.0
}

fn dbm_to_percent(signal_dbm: i16) -> u16 {
    let clamped = signal_dbm.clamp(-100, -30);
    (((clamped + 100) as f32 / 70.0) * 100.0).round() as u16
}

pub fn human_channel_label(channel: u16) -> Cow<'static, str> {
    match infer_band(channel) {
        Band::Ghz24 => Cow::Owned(format!("{channel} (2.4)")),
        Band::Ghz5 => Cow::Owned(format!("{channel} (5)")),
        Band::Unknown => Cow::Owned(channel.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_empty_24ghz_channel() {
        let analysis = Analysis::from_networks(vec![
            Network {
                ssid: "A".into(),
                channel: 1,
                signal_dbm: -42,
                security: "WPA2".into(),
                band: Band::Ghz24,
            },
            Network {
                ssid: "B".into(),
                channel: 6,
                signal_dbm: -50,
                security: "WPA2".into(),
                band: Band::Ghz24,
            },
        ]);

        let recommended = analysis
            .recommendation_24
            .best_channel
            .as_ref()
            .map(|score| score.channel);
        assert!(matches!(recommended, Some(10 | 11)));
    }

    #[test]
    fn tracks_exact_matches_for_5ghz() {
        let analysis = Analysis::from_networks(vec![
            Network {
                ssid: "A".into(),
                channel: 36,
                signal_dbm: -41,
                security: "WPA3".into(),
                band: Band::Ghz5,
            },
            Network {
                ssid: "B".into(),
                channel: 149,
                signal_dbm: -70,
                security: "WPA2".into(),
                band: Band::Ghz5,
            },
        ]);

        let open_channel = analysis
            .channels_5
            .iter()
            .find(|score| score.channel == 40)
            .expect("channel 40 exists");
        assert_eq!(open_channel.network_count, 0);
    }
}
