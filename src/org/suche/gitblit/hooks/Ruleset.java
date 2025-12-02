package org.suche.gitblit.hooks;

import java.security.MessageDigest;
import java.util.Collection;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.MatchResult;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.moandjiezana.toml.Toml;

public record Ruleset(Map<String, Rule> ruleMap, Pattern pattern, Map<Integer,Rule> groupToRule) {
	private static Logger LOG = Logger.getLogger(Ruleset.class.getCanonicalName());
	public record Allowlists(String description, Set<String> paths) { }
	public enum KeywordGroupType { raw,  multi_case }
	public enum CaseVariants {
		CONSTANT_CASE     ("CONSTANT_CASE"   ),
		snake_case        ("snake_case"      ),
		camelCase         ("camelCase"       ),
		kebab_case        ("kebab-case"      ),
		Kebab_Upper_Case  ("Kebab-Upper-Case"),
		PascalCase        ("PascalCase"      ),
		dot_case          ("dot.case"        );
		public String value;
		CaseVariants(final String value) { this.value = value; }
		public static CaseVariants of(final String v) {
			for(final var e : CaseVariants.values()) if(e.value.equals(v)) return e;
			return null;
		}
	}

	/** Context for the LHS side of the assignment-like expression
	 * Patterns for the Left Hand Side (LHS) of assignment expressions, used to reduce false positives.
	 * The LHS typically contains vendor/product names and rule-related keywords, while the RHS contains the vendor pattern (defined in the `regex` property).
	 * These LHS values are automatically combined to generate variable names of all case variants along with the operand in the final assignment-like regex pattern.
	 */
	public record AssignmentContext(
			/* Example:
                        "`azure,api,key`                        => 'azure', 'api' and 'key' will be used to generate variable name in the same order for all case variants",
                "`azure,openai,api|,key`        => 'api|' indicates 'api' as optional",
                "`dd|datadog,api,key`           => 'dd|datadog' indicates either 'dd' or 'datadog' can appear",
                "`azure,app|api|,key`           => 'app|api|' indicates either 'app', 'api' or neither could appear in the between 'azure' and 'key' keywords"
			 */
			String            keywordGroup    , // A comma-separated list of keyword parts used to construct variable names on the left-hand side of assignment expressions. The pipe delimiter (`|`) indicates mutually exclusive alternatives where zero or one keyword may be selected from the associated keyword part. Empty content between pipes, or the keyword part is terminated by a pipe indicates the entire keyword part as optional. Variables in the resulting regex pattern are ordered by their sequential appearance of keyword parts.
			KeywordGroupType  keywordGroupType, // Indicates whether to inject `keywordGroup` directly as provided, or generate multiple case variant combinations for the left-hand side of the expression. This property is mutually exclusive to `caseVariants`, either one can be defined.
			Set<CaseVariants> caseVariants      // Array of case variants to consider when generating the combination of variable names. The variable names in the regex as placed in same order of the case variants are defined. This is useful when we observe a particular case occurs commonly than others, which improves the performance of the regex.
			) {

		public static AssignmentContext of(final Map<String,Object> m) {
			final var            keywordGroup     = (String)m.get("keywordGroup");
			final KeywordGroupType  keywordGroupType = null;
			final Set<CaseVariants> caseVariants     = null;
			System.out.println("AssignmentContext "+m);
			return new AssignmentContext(keywordGroup, keywordGroupType, caseVariants);
		}
	}

	public enum RegexTarget { match, line }
	public enum Condition { AND }

	public record Rule (
			String            id               , // 3...100
			String            description      ,
			String            regex            , // 5...    RE2-compatible regular expression for detecting the secret.
			Double            entropy          ,
			Set<String>       keywords         , //                 List of substrings that must be present to detect a potential secret. Used for efficient substring matching before applying regex matching.
			String            validationRegex  , // 5...    RE2-compatible regular expression for validating secrets match an expected context.
			Set<String>       tags             ,
			Set<String>       examples         , //                 Examples that match the secret detection regex
			Set<String>       negativeExamples , //         Examples of placeholder or non-secret values that should not be flagged as findings.
			AssignmentContext assignmentContext,
			Pattern           path             ,  // 5...   RE2-compatible regular expression for detecting the secret.
			List<Allowlists>  allowlists       ,
			Long              secretGroup
			) {

		final static Pattern PCRE2_0 = Pattern.compile("([^\\\\])[{](?![0-9])");
		final static Pattern PCRE2_1 = Pattern.compile("\\(\\?P<[a-zA-Z]*_[a-zA-Z_]*>");
		final static Function<MatchResult,String> REP_1 = e ->e.group(0).replace("_", "");

		static Pattern pattern(final String v) {
			if(v == null || v.isEmpty()) return null;
			var p0 =v.replace("{{", "⚡");
			p0 = PCRE2_0.matcher(p0).replaceAll("$1❌");
			p0 = PCRE2_1.matcher(p0).replaceAll(REP_1);
			p0 = p0.replace("❌","[{]").replace("⚡","[{][{]");
			final var p1 = p0.replace("(?P<", "(?<");
			try {
				// v = v.replace("{", "[{]").replace("(?P<", "(?<");
				return Pattern.compile(p1);
			} catch(final Throwable t) {
				System.out.println(p1);
				LOG.log(Level.WARNING, "pattern[   "+v+"    >  "+p1+"   ] "+t.getMessage());
				System.exit(0);
				return null;
			}
		}

		public record Allowlists(Pattern[] regexes, RegexTarget regexTarget, String description, Pattern[] paths, Condition condition, String[] stopwords) {
			@SuppressWarnings("unchecked")
			public static Allowlists of(final Map<String,Object> m) {
				if(m == null || m.isEmpty()) return null;
				final var regexes     = (List<String>)m.remove("regexes");
				final var paths       = (List<String>)m.remove("paths");
				final var stopwords   = (List<String>)m.remove("stopwords");
				final var regexTarget = (String)m.remove("regexTarget");
				final var description = (String)m.remove("description");
				final var condition   = (String)m.remove("condition");
				if(!m.isEmpty()) System.out.println("Allowlists "+m.size()+" "+m.keySet());
				return new Allowlists((null == regexes     ? null : regexes.stream().map(Rule::pattern).toList().toArray(new Pattern[regexes.size()]))
						,             (null == regexTarget ? null : RegexTarget.valueOf(regexTarget))
						,             description
						,             (null == paths       ? null : paths.stream  ().map(Rule::pattern).toList().toArray(new Pattern[paths  .size()]))
						,             (null == condition   ? null : Condition.valueOf(condition))
						,             (null == stopwords   ? null : stopwords.toArray(new String[stopwords.size()]))
						);

			}

			public static List<Allowlists> of(final List<Map<String,Object>> m) { return (m == null || m.isEmpty() ? null : m.stream().map(Allowlists::of).toList()); }
		}

		static final Function<String, Pattern> regexCompile = t-> { if(null==t) return null; try { return Rule.pattern(t); } catch(final Throwable x) { throw new IllegalStateException("invalid pattern ["+t+"] => "+x.getMessage()); } };

		@SuppressWarnings({ "unchecked"}) public static Rule of(final Map<String,Object> m) {
			final var id    = (String)m.remove("id"              );
			// if("generic-api-key".equals(id)) return null;
			final var rawEntropy = m.remove("entropy");

			final var entropy = switch(rawEntropy) {
			case  null          -> null;
			case final Long   v -> v.doubleValue();
			case final Double v -> v;
			default             -> { System.err.println("Unsupported entropy({"+rawEntropy.getClass().getCanonicalName()+"}"+rawEntropy+")"); yield null; }
			};

			try {
				final var regex = (String)m.remove("regex");
				regexCompile.apply(regex);	// Check if valid
				final var rule = new Rule( id
						,        (String)m.remove("description"     )
						,        regex
						,        entropy
						,        (       m.remove("keywords"        ) instanceof final Collection c ? new TreeSet<>(c) : null)
						,        (String)m.remove("validationRegex" )
						,        (       m.remove("tags"            ) instanceof final Collection c ? new TreeSet<>(c) : null)
						,        (       m.remove("examples"        ) instanceof final Collection c ? new TreeSet<>(c) : null)
						,        (       m.remove("negativeExamples") instanceof final Collection c ? new TreeSet<>(c) : null)
						,        (       m.remove("negativeExamples") instanceof final Map c ? AssignmentContext.of(c) : null)
						,        regexCompile.apply((String)m.remove("path"           ))
						,        Allowlists.of((List<Map<String,Object>>)m.remove("allowlists"))
						,        (Long  )m.remove("secretGroup"    )
						);
				if(!m.isEmpty()) System.err.println("Rule ["+id+"] ignored "+m.keySet());
				return rule;
			} catch(final Throwable t) { LOG.log(Level.WARNING, "ID["+id+"] "+t.getMessage(), t); return null; }
		}
	}

	private static final double log2div = 1.d / Math.log(2);

	public static double shannonEntropy(final String v) {
		if(v == null || v.isEmpty()) return 0;
		final var charCount = new HashMap<Character,AtomicInteger>();
		for(final var c : v.toCharArray()) charCount.computeIfAbsent(c, _->new AtomicInteger()).incrementAndGet();
		final var invLength = 1.0D / v.length();
		return charCount.values().stream().map(e->e.get() * invLength).reduce(0D, (entropy,freq)-> entropy - freq * Math.log(freq) * log2div);
	}

	public static Ruleset ofRules(final List<Rule> rules) {
		MessageDigest MD5; try { MD5 = MessageDigest.getInstance("MD5"); } catch(final Throwable t) { throw new IllegalStateException(t); }
		final Function<String,String> KEY = t -> "K"+HexFormat.of().formatHex(MD5.digest(t.getBytes()));
		final var groupNameToRule = new HashMap<String,Rule>();
		final var p = new StringBuilder();
		rules.stream().filter(r->null!=r.regex).forEach(r->{
			final var k = KEY.apply(r.id);
			groupNameToRule.put(k, r);
			p.append(p.isEmpty()?"":"|").append("(?<"+k+">"+r.regex+")");
		});
		final var pattern = Rule.pattern(p.toString());
		final var namedGroups = pattern.namedGroups();
		final var groupToRule = groupNameToRule.entrySet().stream().collect(Collectors.toMap(e->namedGroups.get(e.getKey()), Map.Entry::getValue));
		final var ruleMap = rules.stream().filter(r->null!=r.regex).collect(Collectors.toMap(Rule::id, Function.identity()));
		return new Ruleset(ruleMap, pattern, groupToRule);
	}

	public Map.Entry<String,Rule> findMatch(final String t) {
		final var m = pattern.matcher(t);
		if (m.find()) {
			final var gc = m.groupCount();
			for(var i = 1; i < gc; i++) {
				if(m.group(i) instanceof final String found) {
					final var rule = groupToRule.get(i);
					if(rule==null) continue;
					String secret = null;
					if(rule.secretGroup != null)           secret = m.group(i + rule.secretGroup.intValue());
					else if(!groupToRule.containsKey(i+1)) secret = m.group(i + 1);
					else                                   secret = found;
					if(null != rule.entropy) {
						final var entropy = shannonEntropy(secret);
						if(entropy >= rule.entropy) return Map.entry(secret, rule);
						System.out.println("Ignore weak["+rule.id+"]["+secret+"]");
						continue;
					}
					return Map.entry(secret, rule);
				}
			}
			throw new IllegalStateException();
		}
		return null;
	}

	public static Ruleset ofListMap(final List<Map<String,Object>> rules) { return ofRules(rules.stream().map(Rule::of).filter(e->null!=e).toList()); }

	@SuppressWarnings("unchecked")
	public static Ruleset of(final String toml) { return Ruleset.ofListMap((List<Map<String,Object>>)new Toml().read(toml).toMap().get("rules")); }

}