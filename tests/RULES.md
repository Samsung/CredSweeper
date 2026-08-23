# CredSweper rules
|Name|Type|Target|Severity|Confidence|Values|
|---|---|---|---|---|---|
|1Password Account Token|pattern|code,doc|high|strong)(|```(?P<value>ops_eyJ[0-9A-Za-z_-]{168,8000})```|
|API|keyword|code|low|moderate)(|```api(?!tal)```|
|AWS AppSync GraphQL API Key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>da2-[a-z0-9]{26})(?![0-9A-Za-z/+])```|
|AWS Client ID|pattern|code,doc|medium|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>(A3T[0-9A-Z]¦ABIA¦ACCA¦AGPA¦AIDA¦AIPA¦AKIA¦ANPA¦ANVA¦AROA¦APKA¦ASCA¦ASIA)[0-9A-Z]{16,17})(?![0-9A-Za-z_+-])```|
|AWS MWS Key|pattern|code,doc|high|strong)(|```(?P<value>amzn\.mws\.[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})(?![0-9A-Za-z_-])```|
|AWS Multi|multi|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>A(KIA¦SIA)[0-9A-Z]{16})(?![0-9A-Za-z_])```|
||||||```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>((?P<a>[A-Z])¦(?P<b>[a-z])¦(?P<c>[0-9/+])){40,44}(?(a)(?(b)(?(c)\b¦(?!x)x)¦(?!x)x)¦(?!x)x))(?![0-9A-Za-z/+])```|
|AWS S3 Bucket|pattern|code,doc|info|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>[a-z0-9.-]{3,63}\.s3\.amazonaws\.com¦[a-z0-9.-]{3,63}\.s3-website[.-](eu¦ap¦us¦ca¦sa¦cn))```|
|Age Secret Key|pattern|code,doc|high|strong)(|```(?P<value>AGE-SECRET-KEY-1[0-9A-Z]{58})```|
|Akamai Credentials|pattern|code,doc|high|strong)(|```(?P<value>akab-[0-9a-z]{16}-[0-9a-z]{16})(?!\.[0-9a-z-]{1,80}\.akamaiapis\.net)```|
|Alibaba Access Key ID|pattern|code,doc|medium|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>LTAI[0-9A-Za-z]{12,20})(?![0-9A-Za-z_+-])```|
|Alibaba Multi|multi|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>LTAI[0-9A-Za-z]{12,20})(?![0-9A-Za-z_+-])```|
||||||```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>((?P<a>[A-Z])¦(?P<b>[a-z])¦(?P<c>[0-9/+])){30}(?(a)(?(b)(?(c)\b¦(?!x)x)¦(?!x)x)¦(?!x)x))(?![0-9A-Za-z/+])```|
|Amazon Bedrock API Key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>(ABSK¦bedrock-api-key-)[0-9A-Za-z/+]{28,800})(?![0-9A-Za-z/+])```|
|Anthropic API Key|pattern|code,doc|high|strong)(|```(?P<value>sk-ant-api03-[0-9A-Za-z_-]{64,128})(?![0-9A-Za-z_-])```|
|Atlassian PAT token|pattern|code,doc|high|strong)(|```(?P<value>ATATT3xFfGF0[0-9A-Za-z_-]{80,800}(\\?=¦%3[dD])[A-F0-9]{8})```|
|Auth|keyword|code|medium|moderate)(|```auth(?!ors?(?!i[tz]))```|
|Azure Access Token|pattern|code,doc|high|strong)(|```(?P<value>eyJ[=0-9A-Za-z_-]{50,500}\.eyJ[=0-9A-Za-z_-]{8,8000}\.[=0-9A-Za-z_-]{18,800})```|
|Azure Secret Value|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>[0-9A-Za-z_~.-]{3}8Q~[0-9A-Za-z_~.-]{34})(?![0-9A-Za-z_-])```|
|Azure Storage Account Key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>[0-9A-Za-z]{52}JQQJ9[9DH][0-9A-Za-z]{26}([0-9A-Za-z=]{4})?)(?![0-9A-Za-z_/+-])```|
|BASE64 Private Key|pattern|code,doc|high|strong)(|```(?P<value>MII[A-Za-f][0-9A-Za-z/+]{8}(?s:[^!#$&()*\-.:;<=>?@\[\]^_{¦}~]{8,8000}))```|
|BASE64 encoded PEM Private Key|pattern|code,doc|high|strong)(|```(?P<value>[0-9A-Za-z_/+-]{0,8000}LS0t(LS1CRUdJTiB¦LUJFR0lOI¦QkVHSU4g)[0-9A-Za-z_/+-]{0,11}(UFJJVkFURSBLRVkt¦QUklWQVRFIEtFWS0t¦FBSSVZBVEUgS0VZ)[0-9A-Za-z_/+-]{1,8000}LS0t[0-9A-Za-z_/+-]{1,8000})```|
|Basic Authorization|pattern|code,doc|medium|strong)(|```(?P<variable>(?i:basic))(?P<separator>\s+)(?P<value>[=0-9A-Za-z_/+-]{8,8000})(?![0-9A-Za-z_/+-])```|
|Bearer Authorization|pattern|code,doc|medium|moderate)(|```(?P<variable>(?i:bearer¦ntlm))(?P<separator>\s+)(?P<value>[.0-9A-Za-z_/+-]{32,8000}=*)(?![0-9A-Za-z_/+-])```|
|Bitbucket App Password|pattern|code,doc|high|strong)(|```(?P<value>ATBB[0-9A-Za-z]{24}[A-F0-9]{8})(?![0-9A-Za-z_])```|
|Bitbucket HTTP Access Token|pattern|code,doc|high|strong)(|```(?P<value>BBDC-[MNO][ADQTgjwz][AEIMQUYcgk][012345wxyz][0-9A-Za-z_-]{40})```|
|Bitbucket Repository Access Token|pattern|code,doc|high|strong)(|```(?P<value>ATCTT3xFfGN0[0-9A-Za-z_-]{80,800}(\\?=¦%3[dD])[A-F0-9]{8})```|
|Brevo API Key|pattern|code,doc|high|strong)(|```(?P<value>xkeysib-[0-9a-f]{64}-[0-9A-Za-z_-]{16})```|
|CMD ConvertTo-SecureString|pattern|code,doc|high|moderate)(|```(?P<variable>ConvertTo-SecureString(\s\s*-(String¦AsPlainText¦Force))*)\s\s*(?P<value_leftquote>(\\?[\"']){1,3})?(?P<value>(?(value_leftquote)[^\"'\\]¦[^\s\"'\\]){4,800})(?(value_leftquote)(?P<value_rightquote>(\\?[\"']){1,3}))```|
|CMD Password|pattern|code,doc|high|moderate)(|```(^¦\W¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<variable>-[A-Za-z_-]*(?i:pass(in¦out¦word¦phrase)))(\s¦\\?[\"'],)\s*(?!-)(?P<value_leftquote>(\\?[\"']){1,3})?(pass:)?(?!file:¦env:¦fd:)(?P<value>(?(value_leftquote)[^\"'\\]¦[^\s\"'\\]){4,80})(?(value_leftquote)(?P<value_rightquote>(\\?[\"']){1,3}))```|
|CMD Secret|pattern|code,doc|high|moderate)(|```(^¦\W¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<variable>-[A-Za-z_-]*(?i:secret)[A-Za-z_-]*)(\s¦\\?[\"'],)\s*(?!-)(?P<value_leftquote>(\\?[\"']){1,3})?(pass:)?(?!file:¦env:¦fd:)(?P<value>(?(value_leftquote)[^\"'\\]¦[^\s\"'\\]){4,4000})(?(value_leftquote)(?P<value_rightquote>(\\?[\"']){1,3}))```|
|CMD Token|pattern|code,doc|high|moderate)(|```(^¦\W¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<variable>-[A-Za-z_-]*(?i:token¦oauth2-bearer))(\s¦\\?[\"'],)\s*(?!-)(?P<value_leftquote>(\\?[\"']){1,3})?(?P<value>(?(value_leftquote)[^\"'\\]¦[^\s\"'\\]){4,4000})(?(value_leftquote)(?P<value_rightquote>(\\?[\"']){1,3}))```|
|CURL Options|pattern|code,doc|high|weak)(|```(?P<variable>CURLOPT_(XOAUTH2_BEARER¦(?:PROXY)?PASSWORD¦(?:PROXY)?USERPWD)¦KEYPASSWD)\s*,\s*(?P<value_leftquote>")(?P<value>[^"]{4,8000})(?P<value_rightquote>")?```|
|CURL User Password|pattern|code,doc|high|moderate)(|```(?P<variable>curl)\s.*(-[uU]¦--(proxy-)?user)\s\s*(?P<value_leftquote>(\\*[\"']){1,3})?(?(value_leftquote)[^\"'\\:]¦[^\s\"'\\:]){0,64}:(?P<value>(?(value_leftquote)[^\"'\\]¦[^\s\"'\\]){4,64})(?(value_leftquote)(?P<value_rightquote>(\\?[\"']){1,3}))```|
|Clojars Deploy Token|pattern|code,doc|high|strong)(|```(?P<value>CLOJARS_[0-9a-f]{60})(?![0-9A-Za-z_-])```|
|CloudFlare API Token|pattern|code,doc|high|moderate)(|```(?P<value>cf(at¦ut¦k)_[0-9A-Za-z]{48})```|
|Credential|keyword|code|medium|moderate)(|```credential```|
|DOC_CREDENTIALS|pattern|doc|medium|moderate)(|```(?P<wrap>[\"'`(])?\s*(?P<variable>(\w*(?i:(?<!by)passw?o?r?d?s?(?!e[dns]¦ing¦ion¦age)¦pswd¦pwd?\b¦\bp/w\b¦token(?!ize)¦secret¦key(?!word¦board¦pad)¦credential)\w*¦비밀번호¦비번¦패스워드¦키¦암호화?¦토큰))[\"'`]*(\s+(?i:is¦are¦was¦were)(\s*[:-])?\s+¦\s*(?P<separator>설정은¦:=¦:(?!:)¦=(>¦&gt;¦(\\\\*u00¦%)26gt;)¦!==¦!=¦===¦==¦=~¦=¦%3[Dd])\s*)(?P<quote>[\"'`]{1,6})?(?P<value>(?(quote)(?(wrap)[^\"'`)]{4,8000}¦[^\"'`]{4,8000})¦(?(wrap)[^\"'`)]{4,8000}¦\S{4,8000})))```|
|DOC_GET|pattern|doc|medium|moderate)(|```(?P<variable>(\w*(?i:비밀번호¦비번¦패스워드¦키¦암호화?¦토큰¦(?<!by)pass(?!e[dns]¦ing¦ion¦age)¦pswd¦\bpwd?\b¦token(?!ize)¦secret¦key(?!word¦board¦pad)¦cred)\w*)\s*(설정은¦[=:!]{1,3}))?\s*([._0-9A-Za-z\[\]]*get(env)?\s*\(\s*(?(variable)[^,]+¦[\"'\\]*(\\*([\"']¦&(quot¦apos¦#3[49]);)){0,4}(\w*(?i:(?<!by)pass(?!e[dns]¦ing¦ion¦age¦\s+[a-z]{3,64})¦\bpwd?\b¦token¦secret¦key¦cred)\w*))(\\*([\"']¦&(quot¦apos¦#3[49]);)){0,4})\s*(,(\s*default\s*=)?¦\)\s*or)\s*([brufl@]{1,2}(?=\\*[\"'&]))?(?P<lq>(\\*([\"']¦&(quot¦apos¦#3[49]);)){1,4})(?P<value>(.(?!(?P=lq))){4,8000}.?)```|
|Databricks Access Token|pattern|code,doc|medium|strong)(|```(?P<value>dapi[0-9a-f]{32})```|
|DeepSeek API Key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>sk-[0-9a-f]{32,64})(?![0-9A-Za-z_-])```|
|Defined Networking API Key|pattern|code,doc|high|strong)(|```(?P<value>dnkey-[A-Z2-7]{26}-[A-Z2-7]{52})```|
|Digital Ocean Token|pattern|code,doc|high|strong)(|```(?P<value>do[opr]_v1_[a-f0-9]{64})(?![0-9A-Za-z_-])```|
|Discord Bot Token|pattern|code,doc|high|strong)(|```(?P<value>[MNO][ADQTgjwz][AEIMQUYcgk][012345wxyz][0-9A-Za-z_-]{20,24}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{30,40})(?![0-9A-Za-z_-])```|
|Discord Webhook|pattern|code,doc|medium|strong)(|```(?P<variable>discord(?:app)?\.com/api/webhooks)(?P<value>/[0-9]{16,22}/[0-9A-Za-z_-]{40,100})```|
|Docker Access Token|pattern|code,doc|high|strong)(|```(?P<value>dckr_[op]at_[0-9A-Za-z_-]{27,32})```|
|Docker Swarm Key|pattern|code,doc|high|strong)(|```(?P<value>SWMKEY-1-[0-9A-Za-z]{43})```|
|Docker Swarm Token|pattern|code,doc|high|strong)(|```(?P<value>SWMTKN-1-[0-9a-z]{50}-[0-9a-z]{25})```|
|Doppler API Key|pattern|code,doc|high|strong)(|```(?P<value>dp\.pt\.[0-9A-Za-z]{43})```|
|Dropbox API secret (long term)|pattern|code,doc|high|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?=[0-9A-Za-z]{64})(?P<value>[0-9A-Za-z]{10,12}[B-Za-z0-9]A{10,12}[B-Za-z0-9][0-9A-Za-z]{40,44})(?![=0-9A-Za-z_/+-])```|
|Dropbox App secret|pattern|code,doc|info|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>[a-z0-9]{15})(?![=0-9A-Za-z_/+-])```|
|Dropbox OAuth2 API Access Token|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>sl\.(u\.)?[0-9A-Za-z_-]{77,177})(?![0-9A-Za-z_-])```|
|Dynatrace API Token|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>dt0[a-z]{1}[0-9]{2}\.[0-9A-Z]{24}\.[0-9A-Z]{64})(?![0-9A-Za-z_-])```|
|Facebook Access Token|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>EAA[0-9A-Za-z]{80,800})```|
|Facebook App Token|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>[0-9]{12,18}\¦[0-9A-Za-z_-]{24,28})(?![0-9A-Za-z_+-])```|
|Figma Personal Access Token|pattern|code,doc|high|strong)(|```(?P<value>figd_[0-9A-Za-z_-]{40})(?![0-9A-Za-z_-])```|
|Firebase Domain|pattern|code,doc|info|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>[a-z0-9.-]{1,80}\.firebaseio\.com¦[a-z0-9.-]{1,80}\.firebaseapp\.com)```|
|Github App Installation Token|pattern|code,doc|high|strong)(|```(?P<value>ghs_[0-9]{1,20}_eyJ[0-9A-Za-z_-]{15,800}(\.[0-9A-Za-z_-]{0,800}){2,8})```|
|Github Classic Token|pattern|code,doc|high|strong)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>gh[pousr]_[0-9A-Za-z_-]{36,255})```|
|Github Fine-granted Token|pattern|code,doc|high|strong)(|```(?P<value>github_pat_[0-9A-Za-z_]{80,255})```|
|Gitlab Prefix Token|pattern|code,doc|high|strong)(|```(?P<value>(_gitlab_session=¦GR1348941¦gl(agent¦soat¦ffct¦p[at]t¦oas¦cbt¦imt¦rtr¦[dfrw]t)-)[0-9A-Za-z_-]{20,64}(\.[0-9A-Za-z_-]{2,16}){0,2})(?![0-9A-Za-z_-])```|
|Google API Key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>AIza[0-9A-Za-z_-]{35})```|
|Google Multi|multi|code,doc|high|moderate)(|```(?P<value>[0-9]{3,80}-[0-9a-z_]{32}\.apps\.googleusercontent\.com)```|
||||||```\b(?P<value>GOCSPX-[0-9A-Za-z_-]{28}¦((?P<a>[A-Z])¦(?P<b>[a-z])¦(?P<c>[0-9_-])){24,80}(?(a)(?(b)(?(c)\b¦(?!x)x)¦(?!x)x)¦(?!x)x))```|
|Google OAuth Access Token|pattern|code,doc|high|moderate)(|```(?P<value>ya29\.[0-9A-Za-z_-]{22,8000})```|
|Google OAuth Refresh Token|pattern|code,doc|medium|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>1//0[0-9A-Za-z_-]{80,8000})```|
|Google OAuth Secret|pattern|code,doc|high|strong)(|```(?P<value>GOCSPX-[0-9A-Za-z_-]{28})(?![0-9A-Za-z_-])```|
|Grafana Access Policy Token|pattern|code,doc|high|strong)(|```(?P<value>glc_eyJ[0-9A-Za-z_-]{80,360})(?![0-9A-Za-z_-])```|
|Grafana Provisioned API Key|pattern|code,doc|high|strong)(|```(?P<value>eyJ[=0-9A-Za-z_-]{64,360})(?![=0-9A-Za-z_-])```|
|Grafana Service Account Token|pattern|code,doc|high|strong)(|```(?P<value>glsa_[0-9A-Za-z_-]{32}_[0-9A-Fa-f]{8})```|
|Groq API Key|pattern|code,doc|high|strong)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>gsk_[0-9A-Za-z_-]{8,40}(WGdyb3FY¦hncm9xW¦YZ3JvcV)[0-9A-Za-z_-]{8,40})(?![0-9A-Za-z_-])```|
|Hashicorp Terraform Token|pattern|code,doc|high|strong)(|```(?P<value>[0-9A-Za-z_-]{14}\.atlasv1\.[0-9A-Za-z_-]{67})(?![0-9A-Za-z_-])```|
|Hashicorp Vault Token|pattern|code,doc|high|strong)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>hv[brs]\.[0-9A-Za-z_-]{80,160})```|
|Heroku Credentials|pattern|code,doc|high|strong)(|```(?P<value>HRKU-([0-9A-Za-z_-]{60}¦[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}))```|
|Hugging Face User Access Token|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>hf_[0-9A-Za-z_-]{34})(?![0-9A-Za-z_-])```|
|ID_PAIR_PASSWD_PAIR|pattern|doc|medium|moderate)(|```(?P<ddash>--)?(?P<variable>\w*(?i:pa[as]swords?¦passwd?¦pswd¦pwd¦\bp/w¦\bpw¦비밀번호¦비번¦패스워드¦암호))\s*?(?(ddash)[ =]¦[:=/>-]{1,2})\s*(?P<quote>[\"'`]{1,8})?(?P<value>(?-i:(?P<a>[A-Z])¦(?P<b>[a-z])¦(?P<c>[0-9/_+=~!@#$%^&*;:?-])){4,64}(?(a)(?(b)(?(c)(\S¦$)¦(?!x)x)¦(?!x)x)¦(?!x)x))(?(quote)(?P=quote)¦(\s¦$))```|
||||||```(?P<ddash>--)?(?P<variable>(?i:user\s*)?(?i:id¦login¦account¦root¦admin¦user¦name¦wifi¦role¦host¦default¦계정¦아이디))\s*?(?(ddash)[ =]¦[ :=])\s*?(?P<value>\S+)```|
|ID_PASSWD_PAIR|pattern|doc|medium|moderate)(|```(?P<variable>[\w.-]{0,80}(?i:(?P<id>\bid\b)¦id\b¦user¦name¦계정¦아이디)[\w.-]{0,80}(?(id)[ :(/]{1,80}¦[:(/]{1,80})(?i:pa[as]swo?r?ds?¦pswd¦pwd?¦비밀번호¦비번¦패스워드¦암호))\)?(\s*->\s*¦[ =:)(/]{1,80}¦\s+is\s+¦\s+are\s+¦\s*는\s*¦\s*은\s*¦\s*설정은\s*)\(?(?P<id_value>[\w.-]{2,64})[ :\(/\"',]{1,80}(?P<value>(?-i:(?P<a>[A-Z])¦(?P<b>[a-z])¦(?P<c>[0-9/_+=~!@#$%^&*;:?-])){4,64}(?(a)(?(b)(?(c)(\S¦$)¦(?!x)x)¦(?!x)x)¦(?!x)x))```|
|IP_ID_PASSWORD_TRIPLE|pattern|doc|medium|moderate)(|```(^¦\s¦(?P<variable>(?i:\bip[\s/]{1,80}id[\s/]{1,80}pw[\s/:]{0,80}))¦(?P<url>://))(?P<ip>(?<![0-9.])[0-2]?[0-9]{1,2}\.[0-2]?[0-9]{1,2}\.[0-2]?[0-9]{1,2}\.[0-2]?[0-9]{1,2}(?![0-9.]))((\s*[(])?¦(?(variable)[\s,/]{1,80}¦(?(url)[,]¦[,/])))\s*\w[\w.-]{3,80}[\s,/]{1,80}(?P<value>(?(url)(?-i:(?P<a>[A-Z])¦(?P<b>[a-z])¦(?P<c>[0-9_+=~!@#$%^&*;?-])){7,64}(?(a)(?(b)(?(c)(\S¦$)¦(?!x)x)¦(?!x)x)¦(?!x)x)¦(?-i:(?P<e>[A-Z])¦(?P<f>[a-z])¦(?P<g>[0-9/_+=~!@#$%^&*;?-])){7,64}(?(e)(?(f)(?(g)(\S¦$)¦(?!x)x)¦(?!x)x)¦(?!x)x)))(?:\s¦[^/]¦$)```|
|Instagram Access Token|pattern|code,doc|high|strong)(|```(?P<value>IGQVJ[=0-9A-Za-z_-]{100,8000})(?![=0-9A-Za-z_-])```|
|JSON Web Key|pattern|code,doc|medium|strong)(|```(?P<value>\b(e(yJ¦yAi¦woi¦wog¦w0K)¦W(yJ¦3si¦wp7¦wog¦w0K¦3sK))[0-9A-Za-z_+/-]{60,8000})```|
|JSON Web Token|pattern|code,doc|medium|strong)(|```(?P<value>eyJ[=0-9A-Za-z_+/-]{15,8000}(\.[=0-9A-Za-z_+/-]{0,8000}){2,16})(?![=0-9A-Za-z_-])```|
|JWK|multi|code,doc|medium|moderate)(|```(?P<value>['"]?\b(?P<variable>kty)[^0-9A-Za-z_-]{1,8}(RSA¦EC¦oct)\b['"]?)```|
||||||```(?P<variable>\b[dk])[^0-9A-Za-z_-]{1,8}(?P<value>[0-9A-Za-z_-]{22,8000})(?![=0-9A-Za-z_-])```|
|Jfrog Token|pattern|code,doc|high|strong)(|```(?P<value>(cmVmdGtuO[0-9A-Za-z_-]{55}¦AKCp[0-9A-Za-z_-]{69}))(?![0-9A-Za-z_-])```|
|Jira / Confluence PAT token|pattern|code,doc|high|strong)(|```(?<!BBDC-)(?P<value>[MNO][ADQTgjwz][AEIMQUYcgk][012345wxyz][0-9A-Za-z_-]{40})(?![0-9A-Za-z_-])```|
|Key|keyword|code|high|moderate)(|```key(?!word¦board¦pad¦name)```|
|LLAMA API Key|pattern|code,doc|high|strong)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>llx-[0-9A-Za-z_-]{48})```|
|Linear API Key|pattern|code,doc|high|moderate)(|```(?P<value>lin_api_[0-9A-Za-z]{40})```|
|MailChimp API Key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>[0-9A-Za-z_-]{32}-us[0-9]{1,2})(?![0-9A-Za-z_-])```|
|MailGun API Key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>key-[0-9a-z]{32}¦[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8})(?![0-9A-Za-z_-])```|
|NKEY Seed|pattern|code,doc|high|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>S[ACNOPUX][A-Z2-7]{40,200})(?![=0-9A-Za-z_+-])```|
|NPM Token|pattern|code,doc|high|strong)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>npm_[0-9A-Za-z_-]{36,255})```|
|NTLM Token|pattern|code,doc|medium|strong)(|```(?P<value>TlRMTVNTUAA[BCD]AAAA[=0-9A-Za-z_/+-]{28,8000})(?![0-9A-Za-z_/+-])```|
|Netlify Token|pattern|code,doc|medium|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>nfp_[0-9A-Za-z]{36})(?![0-9A-Za-z_-])```|
|NewRelic Credentials|pattern|code,doc|high|moderate)(|```(?P<value>NRAK-[0-9A-Z]{27}¦NRBR-[0-9a-f]{19,20}¦NRII-[0-9A-Za-z_-]{25}¦NRJS-[0-9a-z]{19}¦[0-9a-z]{5}[0-9a-f]{31}NRAL)```|
|Nonce|keyword|code|low|moderate)(|```(?<!\\)nonce```|
|Notion Integration Token|pattern|code,doc|high|strong)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>ntn_[0-9]{9}[0-9A-Za-z_-]{36,255})```|
|NuGet API key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>oy2[a-z0-9]{43})(?![0-9A-Za-z_-])```|
|OTP / 2FA Secret|pattern|code,doc|info|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>([A-Z2-7]{16}){1,2})(?![=0-9A-Za-z_+-])```|
|OpenAI Token|pattern|code,doc|high|strong)(|```(?P<value>sk-[0-9A-Za-z_-]{16,160}(T3BlbkFJ¦9wZW5BS¦PcGVuQU)[0-9A-Za-z_-]{16,160})```|
|PASSWD_PAIR|pattern|doc|medium|moderate)(|```(?P<variable>[\"'`]?(?i:(?<!id[ :/])pa[as]swo?r?ds?¦pswd¦pwd?¦p/w¦비밀번호¦비번¦패스워드¦암호)[\"'`]?)((\s)*(?P<separator>설정은¦:=¦:(?!:)¦=(>¦&gt;¦(\\\\*u00¦%)26gt;)¦!==¦!=¦===¦==¦=~¦=¦%3[Dd])(\s)*)(?P<quote>[\"'`(])?(?P<value>(?-i:(?P<a>[A-Z])¦(?P<b>[a-z])¦(?P<c>[0-9/_+=~!@#$%^&*;:?-])){8,64}(?(a)(?(b)(?(c)((?(quote)[^)\"'`]{1,8000}¦([0-9A-Za-z/_+=~!@#$%^&*;:?-]{1,8000}¦\b))¦$)¦(?!x)x)¦(?!x)x)¦(?!x)x))(?(quote)[)\"'`])```|
|PEM Private Key|pem_key|code,doc|high|strong)(|```(?P<value>-----BEGIN(?![^-]*ENCRYPTED)[^-]*PRIVATE[^-]*KEY[^-]*-----)```|
|Password|keyword|code|high|moderate)(|```(?<!by)pass(?!e[dns]¦ing¦ion¦age¦\s+[a-z]{3,80})¦(?<!pro¦sto)p(s¦ss¦as)?w(o?r)?d(?!ump)¦pswr?\b¦(\b¦_)pw(_¦\b)```|
|PayPal Braintree Access Token|pattern|code,doc|high|strong)(|```(?P<value>access_token\$production\$[0-9a-z]{16}\$[0-9a-z]{32})(?![0-9A-Za-z_-])```|
|Perplexity API Key|pattern|code,doc|high|strong)(|```(?P<value>pplx-[0-9A-Za-z_-]{40,64})(?![0-9A-Za-z_-])```|
|Picatic API Key|pattern|code,doc|high|strong)(|```(?P<value>sk_live_[0-9a-z]{32})(?![0-9A-Za-z_-])```|
|PlanetScale Credentials|pattern|code,doc|high|moderate)(|```(?P<value>pscale_(tkn¦oauth¦pw)_[.0-9A-Za-z_-]{32,64})```|
|PostHog Credentials|pattern|code,doc|medium|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>ph[acrsx]_[0-9A-Za-z]{40,60})(?![0-9A-Za-z_-])```|
|Postman Credentials|pattern|code,doc|medium|moderate)(|```(?P<value>(PMAK-[0-9a-f]{24}-[0-9a-f]{34}¦PMAT-[0-9A-Z]{26}))```|
|PyPi API Token|pattern|code,doc|high|strong)(|```(?P<value>pypi-[0-9A-Za-z_-]{150,255})```|
|RubyGems API Key|pattern|code,doc|medium|strong)(|```(?P<value>rubygems_[0-9a-f]{48})```|
|SECRET_PAIR|pattern|doc|medium|moderate)(|```(?P<variable>[\"'`]?(?i:token¦secret¦key¦키¦암호화?¦토큰)[\"'`]?)((\s)*(?P<separator>설정은¦:=¦:(?!:)¦=(>¦&gt;¦(\\\\*u00¦%)26gt;)¦!==¦!=¦===¦==¦=~¦=¦%3[Dd])(\s)*)(?P<quote>[\"'`(])?(?P<value>(?-i:(?P<a>[A-Z])¦(?P<b>[a-z])¦(?P<c>[0-9/_+=~!@#$%^&*;:?-])){8,80}(?(a)(?(b)(?(c)((?(quote)[^)\"'`]{1,8000}¦([0-9A-Za-z/_+=~!@#$%^&*;:?-]{1,8000}¦\b))¦$)¦(?!x)x)¦(?!x)x)¦(?!x)x))(?(quote)[)\"'`])```|
|SQL Password|pattern|code,doc|medium|weak)(|```(\\[nrt]¦\b)(?i:(?P<variable>(CREATE¦ALTER¦SET\s{1,8}PASSWORD¦INSERT(\s{1,8}IGNORE)?¦UPDATE\s{1,8}[^\s;]{1,80})\s{1,8}(LOGIN¦USER¦ROLE¦FOR¦INTO¦SET)\s{1,8}((?!IDENTIFIED¦PASSWORD)[^\s;]{1,80}\s{1,8}¦VALUES\s{0,8}\(){1,8}(IDENTIFIED((\s{1,8}WITH\s{1,8}\S{1,80})?\s{1,8}(BY¦AS))¦(=¦WITH)?\s{0,8}PASSWORD\b(\s{0,8}=)?)))\s{0,8}(?P<wrap>[(]\s{0,8})?(?P<value_leftquote>((?P<esq>\\{1,8})?([\"'`]¦&(quot¦apos¦#3[49]);)){1,4})?(?P<value>(?(value_leftquote)((?!(?P=value_leftquote))(?(esq)((?!(?P=esq)([\"'`]¦&(quot¦apos¦#3[49]);)).)¦((?!(?P=value_leftquote)).)))¦(?!&(quot¦apos¦#3[49]);)(\\{1,8}([ tnr]¦[^\s\"'`])¦[^\s\"'`,;\\])){3,80})(?(value_leftquote)(?P<value_rightquote>(?<!\\)(?P=value_leftquote))¦(?(wrap)[)]¦[\s\"'`,;]))```|
|Salesforce Credentials|pattern|code,doc|medium|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>(3MVG[0-9A-Za-z_.]{24,200}¦00D[0-9A-Za-z]{9,15}(![0-9A-Za-z_.]{24,200})?))(?![0-9A-Za-z_.])```|
|Salt|keyword|code|low|moderate)(|```salt```|
|Secret|keyword|code|medium|moderate)(|```secret```|
|SendGrid API Key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>SG\.[0-9A-Za-z_-]{16,32}\.[0-9A-Za-z_-]{16,64})```|
|Sentry Organization Auth Token|pattern|code,doc|high|strong)(|```(?P<value>sntrys_eyJ[0-9A-Za-z_-]{80,8000}=*([0-9A-Za-z_-]{32,256})?)(?![0-9A-Za-z_-])```|
|Sentry User Auth Token|pattern|code,doc|high|strong)(|```(?P<value>sntryu_[0-9a-f]{64})(?![0-9A-Za-z_-])```|
|Shopify Token|pattern|code,doc|high|strong)(|```(?P<value>shp(at¦ca¦pa¦ss¦tka)_[0-9A-Fa-f]{32})(?![0-9A-Za-z_-])```|
|Slack Token|pattern|code,doc|high|strong)(|```(?P<value>(xapp¦xox[a-z])\-[0-9A-Za-z-]{10,250})(?![0-9A-Za-z_-])```|
|Slack Webhook|pattern|code,doc|medium|strong)(|```(?P<variable>hooks\.slack\.com/services)(?P<value>/T[0-9A-Z]{8,16}/B[0-9A-Z]{8,16}/[0-9A-Za-z_]{24})```|
|SonarQube Credentials|pattern|code,doc|medium|moderate)(|```(?P<value>sq[apu]_[0-9a-f]{40})(?![0-9A-Za-z_-])```|
|Square Access Token|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>EAAA[0-9A-Za-z_-]{60})(?![0-9A-Za-z_-])```|
|Square Credentials|pattern|code,doc|medium|strong)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>sq0[a-z]{3}-[0-9A-Za-z_-]{22}([0-9A-Za-z_-]{21})?)(?![0-9A-Za-z_-])```|
|Stripe Credentials|pattern|code,doc|high|strong)(|```(?P<value>(whsec¦[prs]k_(test¦live))_[0-9A-Za-z]{24,160})```|
|Supabase Credentials|pattern|code,doc|medium|strong)(|```(?P<value>sbp_(v0_)?[0-9a-f]{40})```|
|Tavily API Key|pattern|code,doc|high|strong)(|```(?P<value>tvly-[0-9A-Za-z_-]{32,40})(?![0-9A-Za-z_-])```|
|Telegram Bot API Token|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>[0-9]{8,10}:[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])```|
|Tencent WeChat API App ID|pattern|code,doc|medium|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>wx[0-9a-f]{16})(?![0-9A-Za-z_-])```|
|Together AI API Key|pattern|code,doc|high|strong)(|```(?P<value>tgp_v1_[0-9A-Za-z_-]{43})```|
|Token|keyword|code|high|moderate)(|```token(?!ize)```|
|Twilio Credentials|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>(AC¦AD¦AL¦CA¦CF¦CL¦CN¦CR¦FW¦IP¦KS¦MM¦NO¦PK¦PN¦QU¦RE¦SC¦SD¦SK¦SM¦TR¦UT¦XE¦XR)[0-9A-Fa-f]{32})(?![0-9A-Za-z_+-])```|
|URL Credentials|pattern|code,doc|high|moderate)(|```(?P<value_leftquote>[\"'])?(?P<variable>[+0-9A-Za-z-]{2,80}://)([^\s\'"<>\[\]^~`{¦}:/]{0,80}:){1,3}(?P<value>[^\s\'"<>\[\]^~`{¦}@:/]{3,80})@[^\s\'"<>\[\]^~`{¦}@:/]{1,800}\\{0,8}(?P<value_rightquote>[\"'])?```|
|UUID|pattern|code,doc|info|strong)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}¦[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12})(?![0-9A-Za-z_+-])```|
|Vercel Token|pattern|code,doc|medium|weak)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>vcp_[0-9A-Za-z]{56})(?![0-9A-Za-z_-])```|
|WunderGraph API Key|pattern|code,doc|medium|strong)(|```(?P<value>cosmo_[0-9a-f]{32})```|
|X AI API Key|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>xai-[0-9A-Za-z_-]{80})(?![0-9A-Za-z_-])```|
|X App-Only Authentication Bearer Token|pattern|code,doc|high|moderate)(|```(?:^¦/¦[^\\0-9A-Za-z+_-]¦\\[0abfnrtv]¦(?:%¦\\x)[0-9A-Fa-f]{2}¦\\[0-7]{3}¦\\[Uu][0-9A-Fa-f]{4}¦\x1B\[[0-9;]{0,80}m)(?P<value>AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{40,42}%3D[0-9A-Za-z]{50})(?![=0-9A-Za-z_/+-])```|
