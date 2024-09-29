use std::env;
// use std::fs;
use clap::{command, arg};
use rand::seq::SliceRandom;
use arboard::{Clipboard, Error};
// use std::io::Write;

// Base word list has approx 466k words. Recommended security strength is 128 bits.
// Equivalent to 2^128 possibilities. To match, need log_(466k) 2^128 ~ 6.7 words.
// But for most applications, 80 bits should be enough, which is ~ 4.2 words.
// This applies for both the full word list and the json dictionary of more common words.

// For SYLLABLES, it's a bit different. We have a list of 322 syllables.
// That requires ~ 15.3 syllables for 128-bit security, and ~ 9.6 for 80-bit.

// Of course, we may want to assume that attackers try all alphabetic passwords first,
// in which case we need a minimum of 27 characters for 128-bit security and 17 characters for 80-bit.

// To get past strength checkers, can just append -Q1! to the end. We call this part the suffix.
// As long as the base is secure enough, it doesn't matter that the suffix is always the same.

// Default: low security (80-bit), space-separated words, no suffix.

// If I use the sub8 word list, with 149,188 words, takes 7.5 words for 128-bit security.
// 4.6 words for 80-bit security. That seems much better actually. 5/8.

// If I use the sub7 word list, with 97,561 words, takes 7.7 words for 128-bit security.
// 4.8 words for 80-bit security. That's even better!

// Using the sub6 word list crosses the 5/8 threshold. So we'll use the sub7 word list.

const RAW_WORDS: &str = include_str!("../words/words_sub7.txt");
const RAW_SYLLABLES: &str = include_str!("../words/common-syllables.txt");

fn main() -> Result<(), Error> {
    let lower_words = RAW_WORDS.to_lowercase();
    let lower_syllables = RAW_SYLLABLES.to_lowercase();

    let all_words: Vec<&str> = lower_words
        .split_ascii_whitespace()
        .collect();
    let all_syllables: Vec<&str> = lower_syllables
        .split_ascii_whitespace()
        .collect();

    // let lower_bw = RAW_BW.to_lowercase();
    // let all_bw: Vec<&str> = lower_bw
    //     .split_ascii_whitespace()
    //     .collect();
    // let mut to_write = fs::File::create("words/words_sub6.txt").unwrap();
    // for word in &all_bw {
    //     if word.len() <= 6 {
    //         to_write.write_all(word.as_bytes()).unwrap();
    //         to_write.write_all("\n".as_bytes()).unwrap();
    //     }
    // }

    let matches = command!()
        .arg(
            arg!(--long "generate a long (>128bit security) passphrase")
            .action(clap::ArgAction::SetTrue))
        .arg(
            arg!(--syll "generate a passphrase with syllables, rather than whole words")
            .action(clap::ArgAction::SetTrue))
        .arg(
            arg!(--quiet "quiet mode: copy to clipboard without displaying")
            .action(clap::ArgAction::SetTrue))
        .arg(
            arg!(--suffix <SUFFIX> "include a suffix to satisfy strength meters, default is \"Q1!\"")
            .action(clap::ArgAction::Set)
            .require_equals(true)
            .num_args(0..=1)
            .default_value("")  // If option is ommitted
            .default_missing_value("Q1!")) // If option is specified without a value
        .arg(
            arg!(--sep <SEP> "separator to use between words or syllables")
            .action(clap::ArgAction::Set)
            .require_equals(true))
        .get_matches();

    let syll = matches.get_flag("syll");
    let long = matches.get_flag("long");
    let min_length = if long { 27 } else { 17 };
    let pool = if syll { all_syllables } else { all_words };
    let quiet = matches.get_flag("quiet");

    let num_chunks = if long {
        if syll { 16 } else { 8 } // long passphrases are 16 syllables or 8 words
    } else {
        if syll { 10 } else { 5 } // short passphrases are 10 syllables or 5 words
    };

    let suffix: &String = matches
        .get_one::<String>("suffix").unwrap();
    let sep: String = matches
        .get_one::<String>("sep")
        .cloned()
        .unwrap_or(if syll { "".into() } else { " ".into() });

    let mut chunks: Vec<&str>;
    loop {
        chunks = pool
            .choose_multiple(&mut rand::thread_rng(), num_chunks)
            .map(|x| *x)
            .collect();

        // Can't use passphrases with a total length under min_length, or else
        // simple alphabetic crackers could break them. Luckily this only happens
        // very rarely.
        if chunks.iter().map(|x| x.len()).sum::<usize>() > min_length { break; }
        else {
            eprintln!("passphrase too short, trying again...");
        }
    }

    let mut result = chunks.join(&sep);

    if suffix.len() > 0 {
        result.push_str(&sep);
        result.push_str(&suffix);
    }

    let mut clipboard = Clipboard::new()?;
    clipboard.set_text(&result)?;

    if !quiet {
        println!("{result}");
    }

    Ok(())
}