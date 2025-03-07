import re


class KeywordPattern:
    """Pattern set of keyword types"""
    key_left = r"(\\[nrt]|%[0-9a-f]{2})?" \
               r"(?P<variable>(([`'\"]{1,8}[^:='\"`}<>\\/&?]*|[^:='\"`}<>\s()\\/&?;,%]*)" \
               r"(?P<keyword>"
    # there will be inserted a keyword
    key_right = r")" \
                r"[^%:='\"`<>{?!&]*" \
                r")" \
                r"(&(quot|apos);|%[0-9a-f]{2}|[`'\"])*" \
                r")"  # <variable>
    separator = r"(\s|\\{1,8}[tnr])*\]?(\s|\\{1,8}[tnr])*" \
                r"(?P<separator>:(\s[a-z]{3,9}[?]?\s)?=|:|=(>|&gt;|\\u0026gt;)|!==|!=|===|==|=|%3d)" \
                r"(\s|\\{1,8}[tnr])*"
    # might be curly, square or parenthesis with words before
    wrap = r"(?P<wrap>(" \
           r"(new(\s|\\{1,8}[tnr]){1,8})?" \
           r"([0-9a-z_.]|-(>|(&|\\\\*u0026)gt;))*" \
           r"[\[\(\{]" \
           r"(\s|\\{1,8}[tnr])*" \
           r"([0-9a-z_]{1,32}=)?" \
           r"){1,8})?"
    string_prefix = r"(((b|r|br|rb|u|f|rf|fr|l|@)(?=(\\*[`'\"])))?"
    left_quote = r"(?P<value_leftquote>((?P<esq>\\{1,8})?([`'\"]|&(quot|apos);)){1,4}))?"
    # Authentication scheme ( oauth | basic | bearer | apikey ) precedes to credential
    auth_keywords = r"(\s?(oauth|bot|basic|bearer|apikey|accesskey|ssws|ntlm)\s)?"
    value = r"(?P<value>" \
            r"(?(value_leftquote)" \
            r"(" \
            r"(?!(?P=value_leftquote))" \
            r"(?(esq)((?!(?P=esq)([`'\"]|&(quot|apos);)).)|((?!(?P=value_leftquote)).)))" \
            r"|" \
            r"(?!&(quot|apos);)" \
            r"(\\{1,8}([ tnr]|[^\s`'\"])" \
            r"|" \
            r"(?P<url_esc>%[0-9a-f]{2})" \
            r"|" \
            r"(?(url_esc)[^\s`'\",;\\&]|[^\s`'\",;\\])" \
            r")){3,8000}" \
            r"|(\{[^}]{3,8000}\})" \
            r"|(<[^>]{3,8000}>)" \
            r")"  # <value>
    right_quote = r"(?(value_leftquote)" \
                  r"(?P<value_rightquote>(?<!\\)(?P=value_leftquote)|\\$|(?<=[0-9a-z+_/-])$)" \
                  r"|" \
                  r"(?(wrap)[\]\)\},;]))"

    @classmethod
    def get_keyword_pattern(cls, keyword: str) -> re.Pattern:
        """Returns compiled regex pattern"""
        expression = ''.join([  #
            cls.key_left,  #
            keyword,  #
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
