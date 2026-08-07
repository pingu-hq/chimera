
const STEP_BUDGET: i64 = 10_000_000;

#[derive(Debug)]
pub struct Regex {
    ast: Node,
    nslots: usize,
}

#[derive(Debug)]
enum Node {
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    Char(char),
    Any,
    Class { lo: u32, hi: u32, neg: bool },
    ClassList { neg: bool, ranges: Vec<(u32, u32)> },
    Set(Set),
    Group(usize, Box<Node>),
    Start,
    End,
    Repeat { inner: Box<Node>, min: usize, max: usize, lazy: bool },
}

#[derive(Debug, Clone, Copy)]
enum Set {
    Digit,
    NonDigit,
    Word,
    NonWord,
    Space,
    NonSpace,
}

impl Set {
    fn is_match(&self, c: char) -> bool {
        match self {
            Set::Digit => c.is_ascii_digit(),
            Set::NonDigit => !c.is_ascii_digit(),
            Set::Word => c.is_ascii_alphanumeric() || c == '_',
            Set::NonWord => !(c.is_ascii_alphanumeric() || c == '_'),
            Set::Space => c.is_whitespace(),
            Set::NonSpace => !c.is_whitespace(),
        }
    }
}

type Slots = Vec<Option<usize>>;

impl Regex {
    pub fn new(pattern: &str) -> Result<Regex, ()> {
        let mut p = Parser::new(pattern);
        let ast = p.parse_alt()?;
        p.expect_end()?;
        if p.ngroup > 64 {
            return Err(());
        }
        Ok(Regex { ast, nslots: 2 * p.ngroup })
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.find(text).is_some()
    }

    /// byte offset of the first (substring) match, if any.
    pub fn find(&self, text: &str) -> Option<usize> {
        let starts = char_starts(text);
        let chars: Vec<char> = text.chars().collect();
        for start in 0..=chars.len() {
            let mut slots: Slots = vec![None; self.nslots];
            let mut budget = STEP_BUDGET;
            if seq_full(&[&self.ast], 0, &chars, start, &mut slots, &mut budget).is_some() {
                return Some(starts[start]);
            }
        }
        None
    }

    /// replace the first match. in the replacement, `$0`/`$&` expand to the
    /// whole match and `$1`..`$9` / `\1`..`\9` to captured groups (empty when a
    /// group did not participate).
    pub fn replace(&self, text: &str, replacement: &str) -> String {
        let starts = char_starts(text);
        let chars: Vec<char> = text.chars().collect();
        for start in 0..=chars.len() {
            let mut slots: Slots = vec![None; self.nslots];
            let mut budget = STEP_BUDGET;
            if let Some(end) = seq_full(&[&self.ast], 0, &chars, start, &mut slots, &mut budget) {
                slots[0] = Some(start);
                slots[1] = Some(end);
                let si = starts[start];
                let ei = starts[end];
                let mut out = String::new();
                out.push_str(&text[..si]);
                out.push_str(&expand(text, &starts, &slots, replacement));
                out.push_str(&text[ei..]);
                return out;
            }
        }
        text.to_string()
    }
}

fn char_starts(text: &str) -> Vec<usize> {
    let mut v = Vec::with_capacity(text.len() + 1);
    v.push(0);
    let mut off = 0;
    for ch in text.chars() {
        off += ch.len_utf8();
        v.push(off);
    }
    v
}

/// match `items[idx..]` as a sequence; used for the whole regex and for every
/// `seq` node. this is the continuation-aware matcher: a `repeat` in the middle
/// of the sequence can backtrack by waking the rest of the list.
fn seq_full(
    items: &[&Node],
    idx: usize,
    chars: &[char],
    pos: usize,
    slots: &mut Slots,
    budget: &mut i64,
) -> Option<usize> {
    if idx == items.len() {
        return Some(pos);
    }
    let node = items[idx];
    match node {
        Node::Repeat { inner, min, max, lazy } => repeat_here(
            inner, *min, *max, *lazy, chars, pos, slots, budget, Some(&items[idx + 1..]),
        ),
        _ => {
            let p = node_full(node, chars, pos, slots, budget)?;
            seq_full(items, idx + 1, chars, p, slots, budget)
        }
    }
}

/// match a single node (once) at `pos`, recursing through groups/alts/segs. a
/// stray `repeat` (not at a seq boundary, e.g. inside a group) matches against
/// an empty continuation (just onwards to whatever follows the group).
fn node_full(
    node: &Node,
    chars: &[char],
    pos: usize,
    slots: &mut Slots,
    budget: &mut i64,
) -> Option<usize> {
    match node {
        Node::Seq(items) => {
            let refs: Vec<&Node> = items.iter().collect();
            seq_full(&refs, 0, chars, pos, slots, budget)
        }
        Node::Alt(branches) => {
            for b in branches {
                if let Some(e) = node_full(b, chars, pos, slots, budget) {
                    return Some(e);
                }
            }
            None
        }
        Node::Char(c) => {
            *budget -= 1;
            if *budget < 0 || pos >= chars.len() || chars[pos] != *c {
                None
            } else {
                Some(pos + 1)
            }
        }
        Node::Any => {
            *budget -= 1;
            if *budget < 0 || pos >= chars.len() {
                None
            } else {
                Some(pos + 1)
            }
        }
        Node::Class { lo, hi, neg } => {
            *budget -= 1;
            if *budget < 0 || pos >= chars.len() {
                return None;
            }
            let cp = chars[pos] as u32;
            if (cp >= *lo && cp <= *hi) != *neg {
                Some(pos + 1)
            } else {
                None
            }
        }
        Node::ClassList { neg, ranges } => {
            *budget -= 1;
            if *budget < 0 || pos >= chars.len() {
                return None;
            }
            let cp = chars[pos] as u32;
            if ranges.iter().any(|&(lo, hi)| cp >= lo && cp <= hi) != *neg {
                Some(pos + 1)
            } else {
                None
            }
        }
        Node::Set(s) => {
            *budget -= 1;
            if *budget < 0 || pos >= chars.len() || !s.is_match(chars[pos]) {
                None
            } else {
                Some(pos + 1)
            }
        }
        Node::Start => {
            if pos == 0 {
                Some(pos)
            } else {
                None
            }
        }
        Node::End => {
            if pos == chars.len() {
                Some(pos)
            } else {
                None
            }
        }
        Node::Group(idx, inner) => {
            match node_full(inner, chars, pos, slots, budget) {
                Some(e) => {
                    slots[2 * idx] = Some(pos);
                    slots[2 * idx + 1] = Some(e);
                    Some(e)
                }
                None => None,
            }
        }
        Node::Repeat { inner, min, max, lazy } => {
            repeat_here(inner, *min, *max, *lazy, chars, pos, slots, budget, None)
        }
    }
}

/// handle a quantifier over `inner` with an optional continuation (the rest of
/// the enclosing sequence). greedy: it consumes then backtracks; lazy: it
/// consumes as few as possible. the budget is a *credit* that grows as nodes
/// are visited; when it goes bodeeo/negative we bail against runaway patterns.
fn repeat_here(
    inner: &Node,
    min: usize,
    max: usize,
    lazy: bool,
    chars: &[char],
    pos: usize,
    slots: &mut Slots,
    budget: &mut i64,
    cont: Option<&[&Node]>,
) -> Option<usize> {
    // mandatory minimum.
    let mut p = pos;
    for _ in 0..min {
        p = node_full(inner, chars, p, slots, budget)?;
    }
    // track the cursor after every *additional* consume so greedy can backtrack.
    let mut stack: Vec<usize> = Vec::new();
    let extra = max.saturating_sub(min);

    if lazy {
        // fewest first: try the continuation, else try one more repetition.
        loop {
            if let Some(e) = cont_apply(cont, chars, p, slots, budget) {
                return Some(e);
            }
            if stack.len() >= extra {
                return None;
            }
            let p2 = node_full(inner, chars, p, slots, budget)?;
            if p2 == p {
                return None; // avoid empty-inner infinite loop
            }
            stack.push(p);
            p = p2;
        }
    } else {
        // greedy: consume as much as possible (up to `extra` more), then
        // backtrack toward the minimum until the continuation matches.
        while stack.len() < extra {
            let Some(p2) = node_full(inner, chars, p, slots, budget) else {
                break; // cannot consume further (end of text / no match)
            };
            if p2 == p {
                break; // inner matched empty: avoid an infinite loop
            }
            stack.push(p);
            p = p2;
        }
        loop {
            if let Some(e) = cont_apply(cont, chars, p, slots, budget) {
                return Some(e);
            }
            match stack.pop() {
                Some(prev) => p = prev,
                None => return None,
            }
        }
    }
}

/// continue after a quantifier: either finish the enclosing sequence at `p`,
/// or (when `cont` is `none`) treat this as the end of a self-contained group.
fn cont_apply(
    cont: Option<&[&Node]>,
    chars: &[char],
    p: usize,
    slots: &mut Slots,
    budget: &mut i64,
) -> Option<usize> {
    match cont {
        Some(items) => seq_full(items, 0, chars, p, slots, budget),
        None => Some(p),
    }
}

/// byte offsets of every char boundary; index k is the offset of the k-th
/// char, the final value is `text.len()`.
fn expand(text: &str, starts: &[usize], slots: &Slots, replacement: &str) -> String {
    let sub = |g: usize| -> String {
        if 2 * g + 1 >= slots.len() {
            return String::new();
        }
        match (slots[2 * g], slots[2 * g + 1]) {
            (Some(a), Some(b)) if a < b => {
                let lo = starts.get(a).copied().unwrap_or(0);
                let hi = starts.get(b).copied().unwrap_or(0);
                if lo <= hi {
                    text[lo..hi].to_string()
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        }
    };
    let bytes = replacement.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if (b == b'$' || b == b'\\') && i + 1 < bytes.len() {
            let nxt = bytes[i + 1];
            if nxt == b'&' {
                out.push_str(&sub(0));
                i += 2;
                continue;
            }
            if nxt.is_ascii_digit() {
                let g = (nxt - b'0') as usize;
                out.push_str(&sub(g));
                i += 2;
                continue;
            }
            out.push(b as char);
            i += 1;
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}


struct Parser {
    c: Vec<char>,
    pos: usize,
    ngroup: usize,
}

impl Parser {
    fn new(s: &str) -> Parser {
        Parser { c: s.chars().collect(), pos: 0, ngroup: 1 }
    }
    fn peek(&self) -> Option<char> {
        self.c.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let ch = self.peek();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }
    fn expect_end(&self) -> Result<(), ()> {
        if self.pos == self.c.len() {
            Ok(())
        } else {
            Err(())
        }
    }

    fn parse_alt(&mut self) -> Result<Node, ()> {
        let mut branches = vec![self.parse_seq()?];
        while self.peek() == Some('|') {
            self.bump();
            branches.push(self.parse_seq()?);
        }
        Ok(if branches.len() == 1 {
            branches.remove(0)
        } else {
            Node::Alt(branches)
        })
    }

    fn parse_seq(&mut self) -> Result<Node, ()> {
        let mut items = Vec::new();
        while let Some(ch) = self.peek() {
            if ch == '|' || ch == ')' {
                break;
            }
            items.push(self.parse_piece()?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            Node::Seq(items)
        })
    }

    fn parse_piece(&mut self) -> Result<Node, ()> {
        let atom = self.parse_atom()?;
        let (min, max) = match self.peek() {
            Some('*') => {
                self.bump();
                (0, usize::MAX)
            }
            Some('+') => {
                self.bump();
                (1, usize::MAX)
            }
            Some('?') => {
                self.bump();
                (0, 1)
            }
            Some('{') => self.parse_braced()?,
            _ => return Ok(atom),
        };
        let lazy = self.peek() == Some('?');
        if lazy {
            self.bump();
        }
        Ok(Node::Repeat { inner: Box::new(atom), min, max, lazy })
    }

    fn parse_braced(&mut self) -> Result<(usize, usize), ()> {
        self.bump(); // '{'
        let mut n1 = String::new();
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            n1.push(self.bump().unwrap());
        }
        let lo = if n1.is_empty() { 0 } else { n1.parse::<usize>().map_err(|_| ())? };
        let (min, max) = match self.peek() {
            Some(',') => {
                self.bump();
                let mut n2 = String::new();
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    n2.push(self.bump().unwrap());
                }
                let hi = if n2.is_empty() { usize::MAX } else { n2.parse::<usize>().map_err(|_| ())? };
                (lo, hi)
            }
            _ => (lo, lo),
        };
        if self.bump() != Some('}') {
            return Err(());
        }
        if min > max {
            return Err(());
        }
        Ok((min, max))
    }

    fn parse_atom(&mut self) -> Result<Node, ()> {
        let c = self.bump().ok_or(())?;
        match c {
            '^' => Ok(Node::Start),
            '$' => Ok(Node::End),
            '.' => Ok(Node::Any),
            '(' => {
                let idx = self.ngroup;
                self.ngroup += 1;
                let inner = self.parse_alt()?;
                if self.bump() != Some(')') {
                    return Err(());
                }
                Ok(Node::Group(idx, Box::new(inner)))
            }
            '[' => self.parse_class(),
            '\\' => self.parse_escape(),
            ')' | '{' | '}' | '*' | '+' | '?' => Err(()),
            other => Ok(Node::Char(other)),
        }
    }

    fn parse_escape(&mut self) -> Result<Node, ()> {
        let c = self.bump().ok_or(())?;
        Ok(match c {
            'd' => Node::Set(Set::Digit),
            'D' => Node::Set(Set::NonDigit),
            'w' => Node::Set(Set::Word),
            'W' => Node::Set(Set::NonWord),
            's' => Node::Set(Set::Space),
            'S' => Node::Set(Set::NonSpace),
            'n' => Node::Char('\n'),
            't' => Node::Char('\t'),
            '0' => Node::Char('\0'),
            'b' => Node::Char('\u{8}'),
            other => Node::Char(other),
        })
    }

    fn parse_class(&mut self) -> Result<Node, ()> {
        let mut neg = false;
        if self.peek() == Some('^') {
            self.bump();
            neg = true;
        }
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        let mut first = true;
        loop {
            let c = self.bump().ok_or(())?;
            if c == ']' && !first {
                break;
            }
            first = false;
            let lo = if c == '\\' {
                self.bump().ok_or(())? as u32
            } else {
                c as u32
            };
            let hi = if self.peek() == Some('-') && self.c.get(self.pos + 1) != Some(&']') {
                self.bump();
                let hb = self.bump().ok_or(())?;
                if hb == '\\' {
                    self.bump().ok_or(())? as u32
                } else {
                    hb as u32
                }
            } else {
                lo
            };
            ranges.push((lo, hi));
        }
        Ok(if ranges.len() == 1 {
            Node::Class { lo: ranges[0].0, hi: ranges[0].1, neg }
        } else {
            Node::ClassList { neg, ranges }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pat: &str, hay: &str) -> bool {
        Regex::new(pat).map(|r| r.is_match(hay)).unwrap_or(false)
    }

    #[test]
    fn basic() {
        assert!(m("abc", "xxabcxx"));
        assert!(!m("abc", "xxabxx"));
        assert!(m("^a.c$", "abc"));
        assert!(!m("^a.c$", "abcc"));
        assert!(m("[0-9]+", "abc123"));
        assert!(!m("^[0-9]+$", "abc123"));
    }

    #[test]
    fn sets_and_anchors() {
        assert!(m("\\d+", "version 42"));
        assert!(m("^\\w+$", "hello_world"));
        assert!(!m("^\\w+$", "has space"));
        assert!(m("[^0-9]", "hello"));
        assert!(!m("[^0-9]", "123"));
    }

    #[test]
    fn ranges() {
        assert!(m("[a-mx-z]+", "quick"));
        assert!(m("a{2,3}", "aaa"));
        assert!(!m("a{4}", "aaa"));
        assert!(m("ab?c", "ac"));
        assert!(m("a+b+c", "aabbc"));
        assert!(m("(cat|dog)", "a dog bark"));
    }

    #[test]
    fn lazy_still_matches() {
        assert!(m("a+?b", "aaab"));
        assert!(m(".*b", "aab"));
    }

    #[test]
    fn replace_with_groups() {
        let re = Regex::new("(capture).*(dig)").unwrap();
        assert_eq!(re.replace("a capture__dig z", "[$1][$2][$0]"), "a [capture][dig][capture__dig] z");
        assert_eq!(Regex::new("a+").unwrap().replace("baa", "<$0>"), "b<aa>");
        assert_eq!(re.replace("nothing here", "[[$1]]"), "nothing here");
    }
}