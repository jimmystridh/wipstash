// Windows CRT argument escaping. Executable is supplied separately to CreateProcessW.
// Shells retain their own command languages; callers must explicitly select them.
// Do not force quotes around ordinary arguments: cmd.exe does not recognize
// quoted switches such as "/D" and "/C". This is not a shell escaping API.
pub(crate) fn quote(argument: &[u16]) -> Vec<u16> {
    if !argument.is_empty()
        && !argument
            .iter()
            .any(|&unit| matches!(unit, 0x20 | 0x09 | 0x22))
    {
        return argument.to_vec();
    }
    let mut result = vec![b'"' as u16];
    let mut slashes = 0;
    for &unit in argument {
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            result.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2 + 1));
        } else {
            result.extend(std::iter::repeat_n(b'\\' as u16, slashes));
        }
        slashes = 0;
        result.push(unit);
    }
    result.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    result.push(b'"' as u16);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escaping_preserves_argument_boundaries() {
        for (input, expected) in [
            ("", "\"\""),
            ("a b", "\"a b\""),
            ("a\"b", "\"a\\\"b\""),
            ("path\\", "path\\"),
            ("path with space\\", "\"path with space\\\\\""),
            ("/D", "/D"),
            ("/C", "/C"),
            ("plain", "plain"),
            ("a\tb", "\"a\tb\""),
        ] {
            assert_eq!(
                String::from_utf16(&quote(&input.encode_utf16().collect::<Vec<_>>())).unwrap(),
                expected
            );
        }
    }
}
