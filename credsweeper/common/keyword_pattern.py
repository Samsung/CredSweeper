import re


class KeywordPattern:
    """Pattern set of keyword types"""
    directive = r"(?P<directive>(?:" \
                r"(?:[#%]define|define(?=(\s|\\{1,8}[tnr])*\()|%global)" \
                r"(?:\s?\(|\s|\\{1,8}[tnr]){1,8}|\bset(?=\b|\w*(\s|\\{1,8}[tnr])*\()" \
                r"))?"
    key_left = r"(?:\\[nrt]|(\\\\*u00|%)[0-9a-f]{2}|\s)*" \
               r"(?P<variable>(([\"'`]{1,8}[^:=\"'`}<>\\/&?]*|[^:=\"'`}<>\s()\\/&?;,%]*)"
    # keyword will be inserted here
    key_right = r"[^%:=\"'`<>({?!&;\n]{0,80}" \
                r")" \
                r"(&(quot|apos|#3[49]);|(\\\\*u00|%)[0-9a-f]{2}|[\"'`])*" \
                r")"  # <variable>
    separator = r"(?(directive)|(\s|\\{1,8}[tnr])*\]?(\s|\\{1,8}[tnr])*)" \
                r"(?P<separator>:(\s[a-z]{3,9}[?]?\s)?=|:(?!:)|=(>|&gt;|(\\\\*u00|%)26gt;)|!==|!=|===|==|=~|=" \
                r"|(?(directive)(,|\\t|\s|\((?!\))){1,80}|%3d))" \
                r"(\s|\\{1,8}[tnr])*"
    # might be curly, square or parenthesis with words before
    wrap = r"(?P<wrap>(" \
           r"((\s|\\{1,8}[tnr]|new|byte|char|string|\[\]){1,8})?" \
           r"(?P<get>([_a-z][0-9a-z_.\[\]]*\.)get|(os\.)?getenv)?" \
           r"([0-9a-z_.]|::|-(>|&gt;))*" \
           r"\s*" \
           r"(\[(?!\])|\((?!\))|\{(?!\}))" \
           r"(\s|\\{1,8}[tnr])*" \
           r"(?(get)('[^']{1,31}'|\"[^\"]{1,31}\")\s*,\s*|)" \
           r"([0-9a-z_]{1,32}\s*[:=]\s*)?" \
           r"){1,8})?"
    string_prefix = r"(((b|r|br|rb|u|f|rf|fr|l|@)(?=(\\*[\"'`])))?"
    left_quote = r"(?P<value_leftquote>((?P<esq>\\{1,8})?([\"'`]|&(quot|apos|#3[49]);)){1,4}))?"
    # Authentication scheme ( oauth | basic | bearer | apikey ) precedes to credential
    auth_keywords = r"(\s?(oauth|bot|basic|bearer|apikey|accesskey|ssws|ntlm)\s)?"
    value = r"(?P<value>" \
            r"(?(value_leftquote)" \
            r"(" \
            r"(?!(?P=value_leftquote))" \
            r"(?(esq)((?!(?P=esq)([\"'`]|&(quot|apos|#3[49]);)).)|((?!(?P=value_leftquote)).)))" \
            r"|" \
            r"(?!&(quot|apos|#3[49]);)" \
            r"(\\{1,8}([ tnr]|[^\s\"'`])" \
            r"|" \
            r"(?P<url_esc>%[0-9a-f]{2})" \
            r"|" \
            r"(?(url_esc)[^\s\"'`,;\\&]|[^\s\"'`,;\\])" \
            r")" \
            r"){4,8000}" \
            r"|" \
            r"(<[^>]{4,8000}>)" \
            r"|" \
            r"(\$?\({1,3}[^)]{4,8000}\){1,3})" \
            r"|" \
            r"(\$?\{{1,3}[^}]{4,8000}\}{1,3})" \
            r"|" \
            r"(?(wrap)(?(value_leftquote)(?!\\(?P=value_leftquote))|[^\]\)\}]){16,8000})" \
            r")"  # <value>
    right_quote = r"(?(value_leftquote)" \
                  r"(?P<value_rightquote>(?<!\\)(?P=value_leftquote)|\\$|(?<=[0-9a-z+_/-])$)" \
                  r"|" \
                  r"(?(wrap)(\]|\)|\}|;|\\|$))" \
                  r")"

    @classmethod
    def get_keyword_pattern(cls, keyword: str) -> re.Pattern:
        """Returns compiled regex pattern"""
        expression = ''.join([  #
            cls.directive,  #
            cls.key_left,  #
            fr"(?P<keyword>{keyword})",  # named group required
            cls.key_right,  #
            cls.separator,  #
            cls.wrap,  #
            cls.string_prefix,  #
            cls.left_quote,  #
            cls.auth_keywords,  #
            cls.value,  #
            cls.right_quote,  #
        ])
        return re.compile(expression, flags=re.IGNORECASE | re.DOTALL)
