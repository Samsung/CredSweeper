import re


class KeywordPattern:
    """Pattern set of keyword types"""
    key_left = r"(\\[nrt])?"\
               r"(?P<variable>(([`'\"]+[^:='\"`}<>\\/&?]*|[^:='\"`}<>\s()\\/&?]*)" \
               r"(?P<keyword>"
    # there will be inserted a keyword
    key_right = r")" \
                r"[^:='\"`<>{?!&]*)[`'\"]*)"  # <variable>
    separator = r"(\s|\\+[tnr])*\]?(\s|\\+[tnr])*" \
                r"(?P<separator>:( [a-z]{3,9}[?]? )?=|:|=(>|&gt;|\\u0026gt;)|!=|===|==|=)" \
                r"(\s|\\+[tnr])*"
    # might be curly, square or parenthesis with words before
    wrap = r"(?P<wrap>(" \
           r"(new(\s|\\+[tnr])+)?" \
           r"([0-9a-z_.]|-(>|(&|\\\\*u0026)gt;))*" \
           r"[\[\(\{]"\
           r"(\s|\\+[tnr])*" \
           r"([0-9a-z_]{1,32}=)?" \
           r")+)?"
    string_prefix = r"(((b|r|br|rb|u|f|rf|fr|l|@)(?=(\\*[`'\"])))?"
    left_quote = r"(?P<value_leftquote>((?P<esq>\\{1,8})?[`'\"]){1,4}))?"
    # Authentication scheme ( oauth | basic | bearer | apikey ) precedes to credential
    auth_keywords = r"( ?(oauth|bot|basic|bearer|apikey|accesskey) )?"
    value = r"(?P<value>" \
            r"(?(value_leftquote)" \
            r"(" \
            r"(?!(?P=value_leftquote))" \
            r"(?(esq)((?!(?P=esq)['`\"]).)|((?!(?P=value_leftquote)).)))" \
            r"|" \
            r"(\\+([ tnr]|[^\s`'\"])|[^\s`'\",;\\])" \
            r"){3,8000}" \
            r"|(\{[^}]{3,8000}\})" \
            r"|(<[^>]{3,8000}>)" \
            r")"
    right_quote = r"(?(value_leftquote)" \
                  r"(?P<value_rightquote>(?<!\\)(?P=value_leftquote)|\\$|(?<=[0-9a-z+_/-])$)" \
                  r"|" \
                  r"(?(wrap)[\]\)\},;]))"

    @classmethod
    def get_keyword_pattern(cls, keyword: str) -> re.Pattern:
        """Returns compiled regex pattern"""
        expression = "".join([  #
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
