#import "@preview/unequivocal-ams:0.1.2": ams-article
#import "@preview/oxifmt:0.2.1": strfmt
#show: ams-article.with(
  title: text(  // Override for readability in PDF.js
    font: "TeX Gyre Termes",
    weight: 700,
    tracking: 0pt,
  )[Detecting Prompt Injections with Integrated Gradients],
  authors: (( name: "Alex Becker" ),),
  abstract: [
Modern LLMs are often given rules to follow via a trusted system prompt and then fed untrusted user prompts.
However, malicious user prompts are frequently able to bypass these rules using techniques known as prompt injections.
Defenses against these attacks have primarily focused on fine-tuning models to recognize them.
These defenses work well on existing attacks but are expected to be vulnerable to novel attacks.
We propose a novel metric for detecting prompt injections based on mechanistic interpretation techniques
rather than fine-tuning, which should complement existing approaches and generalize to novel attacks.
Code & data: #link("https://github.com/alexbecker/prompt-injection")[github.com/alexbecker/prompt-injection]
  ]
)
#show list: set block(below: 1em)
#show enum: set block(below: 1em)
#set text(hyphenate: false)
#let is-num-str = s => s.find(regex("^-?[0-9]+(\\.[0-9]+)?$")) != none
#let fmt = n => if(is-num-str(n)) { strfmt("{:.3}", float(n)) } else { n }
// ── vmerge: collapse identical‑value runs in one column ────────────
// • data  – array of rows (each row is an array/tuple)
// • key   – which column to merge (default 0)
// Returns a sequence you can splat into #table.
//
// Example: #table(..vmerge(data, key: 0))
//
#let vmerge(data, key: 0) = {
  let cols = data.first().len()
  let out  = ()

  let i = 0
  while i < data.len() {
    // length of the run with the same key‑column value
    let span = 1
    while i + span < data.len() and data.at(i + span).at(key) == data.at(i).at(key) {
      span += 1
    }

    // ── first row of the run: key cell with rowspan ──
    let row = ()
    for c in range(cols) {
      if c == key {
        row += (table.cell(rowspan: span)[#data.at(i).at(c)],)
      } else {
        row += (data.at(i).at(c),)
      }
    }
    out += (..row)

    // ── remaining rows: omit key column ──
    for j in range(1, span) {
      let r = ()
      for c in range(cols) {
        if c != key {
          r += (data.at(i + j).at(c),)
        }
      }
      out += (..r)
    }

    i += span
  }

  out
}


= Introduction

If LLMs are to reach their full potential, we will need them to be able to handle untrusted input safely and reliably.
Specifically, organizations and individuals deploying LLMs will need to be able to specify what the LLM should and should not do,
and trust that whatever other non-privileged input the LLM is fed by others will not cause it to ignore these instructions.
This is particularly necessary for deploying LLMs as agents, which must be able to take autonomous actions.

_Prompt injection_---a term coined by Willison in 2022 as an analogy to SQL injections @willison2022 after Goodside’s public demonstration against GPT-3 @goodside2022
but previously reported privately to OpenAI @cefalu2022 ---refers to a loosely-defined collection of techniques used to
trigger an LLM to ignore or modify instructions provided by the author of an LLM-based agent or application.
The term _jailbreak_ is sometimes used interchangeably, but often refers to a broader class of techniques used to elicit other classes of undesirable behavior
such as providing instructions for law-breaking activities.
We use the term prompt injection here to refer to the aforementioned narrower class.

Most LLMs used in agents and applications have been tuned with reinforcement learning to use a chat template which includes distinct
_system prompt_ and _user prompt_ portions and to prioritize instructions in the system prompt,
and official advice from major labs such as OpenAI is for application and agent authors to provide instructions there @openai2025prompting.
This is conceptually similar to how most SQL libraries allow application authors to specify query templates separately from values which may come from the user.
However, the system prompt/user prompt separation does not offer the same guarantee that proper use of SQL libraries does.
Some LLMs are trained via reinforcement learning to prioritize system prompts over user inputs, but the persistence of prompt injection vulnerabilities
shows that this is not sufficiently reliable.

Unlike many problems with current LLMs, prompt injection is not expected to be solved as a side-effect of creating more generally capable LLMs.
In fact, the very ability of more capable LLMs to follow more complex instructions means that they will be vulnerable to more complex attacks.
This makes prompt injection a clear target for dedicated research.

The prompt injection problem has been studied in 2 different settings. _Indirect prompt injection_ assumes that a trusted user provides instructions to the LLM
and then feeds it untrusted data, and the goal of defenses is to prevent any instructions in the data portion from being acted on.
_Direct prompt injection_ goes further, assuming that instructions from an untrusted user should be followed, unless they conflict with instructions from the system author.
In realistic multi-turn or agent settings, it is necessary to handle the direct prompt injection problem because previous LLM outputs contain further
instructions for the LLM to follow but are necessarily tainted by untrusted input.

We focus on a particular class of system prompts for ease of analysis: those that attempt to enforce a _rule_ which will reject certain user prompts.
We call the prompts the rules are intended to reject _malicious prompts_.
This eliminates any ambiguity about what it means for a rule to be enforced, allowing us to ignore malicious prompts which are handled correctly
and focus on distinguishing between benign prompts and successful prompt injections.
While this may appear to be a major restriction, many practical requirements can be realized in this format---for example, the requirement that
a list of transactions balance debits and credits can be converted into the rule "reject attempts to generate a list of transactions that is not balanced".

= Related Work

Broadly speaking, prior work on prompt injection defenses can be divided into detection, model hardening, and capability-based isolation.
We briefly survey these approaches and discuss how applicable they are to our 
Note that this survey is not exhaustive.

== Detection

Detection methods tend to work for both direct and indirect prompt injections, at least as benchmarked in the literature, because the attack methods and objectives typically tested
in both settings have high overlap.
However, we will see in our analysis that this does not perfectly transfer when attack objectives are changed to fit the direct prompt injection scenario.

=== Dedicated Models

Early defenses leverage off‑the‑shelf text‑classification models.  
LLM Guard‑v2 fine‑tunes DeBERTa‑v3 on a composite dataset of known attacks and benign prompts and reports $F_1 approx 0.95$ on its held‑out split @llmguardv2.
Subsequent work shows that shallow classifiers operating wholly in embedding space also reach competitive accuracy while remaining lightweight for on‑device use @ayub2024embedding.

== Model Hardening

More recent approaches introduce logical separation between the trusted and untrusted inputs in the network and fine-tuning the LLM to treat them differently.
*Structured Queries (StruQ)* adds a dedicated delimiter token that splits a query into `⟨prompt⟩` and `⟨data⟩` channels; fine‑tuning with contrastive pairs cuts manual jailbreak success on Llama-7B and Mistral-7B to $<2%$ and significantly reduces the effectiveness of several adversarial methods @Chen2025StruQ.
*SecAlign* builds on this work using a preference‑optimization dataset where "secure" completions obey the system prompt and "insecure" ones follow the injected instruction; RLHF on this dataset drives the success rate of six canonical attacks to $<10%$ on Llama-3-8B-Instruct without harming AlpacaEval scores @secalign2025.

Both StruQ and SecAlign focus on indirect prompt injection.
Direct prompt injection hardening was first attempted by OpenAI, which introduced the *Instruction Hierarchy* dataset containing conflicting sytem, user and tool content,
and fine-tuned GPT-3.5 on it to respect their precedence rules @wallace2024instructionhierarchy.
*Instructional Segment Embedding (ISE)* introduces a three‑way segment embedding (`system` / `user` / `data`) deals with both direct and indirect prompt injection attacks.
Fine-tuning Llama‑2‑7B with ISE improves its performance on both the Instruction Hierarchy dataset and StruQ's indirect prompt injection benchmark @ise2025.

== Capability‑based Isolation

Other work has focused on minimizing the harm a successful prompt injection can cause by requiring user approval for any dangerous action.
The *Dual LLM* pattern proposed by Willison in 2023 pipes the output of an "untrusted" assistant model into a second, policy‑enforcing model that rewrites or refuses unsafe text @willison2023dualllm. While effective against direct prompt injections, it remains vulnerable if the second model blindly trusts the first model’s output and so can still relay hidden adversarial payloads @camel2025 @willison2025camel.

Google DeepMind’s *CaMeL* (Capabilities for Machine Learning) hardens this idea by isolating untrusted input inside a "Quarantined LLM" that has no tool‑calling rights, then passing only a verified, least‑privilege representation to a "Privileged LLM". CaMeL solves 67% of tasks on the AgentDojo benchmark with formal security guarantees and addresses the vulnerability found in Dual LLM @camel2025.

== Taxonomies and Analyses

Also important are several papers that create useful taxonomies of prompt injection attacks, which help us develop and analyze detection approaches.
*Prompt Injection 2.0* proposes a three‑tier taxonomy---multimodal, recursive, hybrid---and shows cross‑site‑script–style chains that bypass current guardrails @mchugh2025pi2.
In addition to introducing a detector, *Indirect PI* catalogues attacks delivered through third‑party content (HTML, e‑mail) @chen2025indirect.  

== Mechanistic Approaches

To our knowledge, there is little previous mechanistic work focused on detecting prompt injections.
*Attention Tracker* experimentally identifies attention heads whose last-token attention drops most when subject to a prompt injection attack.
Averaging attention across these heads to detect prompt injection outperforms Prompt Guard on several common model families and datasets,
but is vulnerable to adversarial methods @hung2025attention.
Although this approach is training-free, it still depends heavily on the dataset used to identify important attention heads.
*Attention Slipping* similarly focuses on the effects of prompt injections on refusal-related attention heads, but proposes a countermeasure
to prevent attention from dropping rather than a detection mechanism @hu2025attentionslipping.

There is also prior work for using gradients to detect safety policy violations, which is similar to our work though not focused specifically on prompt injections.
*GradSafe* computes the cosine similarity between the gradient of "safety‑critical" parameters and a reference vector @xie2024gradsafe.
*Gradient Cuff* considers the gradient of the probability of a refusal response @hu2024gradientcuff-neurips.
*Token Highlighter* builds on this concept by identifying the tokens with the largest such gradient and "soft removing" other tokens by scaling the embeddings
down @hu2025tokenhighlighter.

= Detection Approach

Our intuition for detecting prompt injection attacks is to compare how the user prompt is processed when the rule is present versus when it is not,
in particular analyzing the effect of each token in the user prompt one-by-one.
We use Integrated Gradients ($op("IG")$) @sundararajan2017 to attribute changes in the probability of a given output to individual tokens.

For benign prompts, we expect no difference in the output or in the $op("IG")$ at any token with or without a rule.
For malicious prompts without prompt injection, we expect a large difference in the output and consequently a large difference in the $op("IG")$ at some tokens,
but for our purposes we can ignore this case.
For malicious prompts with successful prompt injection, we expect no difference in output but for the $op("IG")$ to be much larger on the tokens that
form the prompt injection attack.
We offer evidence that this is the case in Appendix 3.

It is worth further considering the case of prompts that are benign, but become malicious when a few tokens are replaced with the baseline used for $op("IG")$.
These tokens will then have a large $op("IG")$ when the rule is present. However, we assume that the corresponding malicious prompts
produce significantly different output, and so the $op("IG")$ of these tokens given the actual output will be positive and large even without the rule.
We examine this case in section 5.2.

In order to minimize changes in the grammatical structure of the prompt and avoid introducing changes due to the positional encoding,
rather than deleting rules entirely we replace them with specially constructed _null rules_ of the same length#footnote[During the initial analysis
of our experimental data, we noticed that our construction of most null rules did not count tokens correctly for the Qwen tokenizer.
This was corrected and the experiment re-run for the Qwen models, resulting in a small but noticeable improvement for Qwen3-8B and
no noticeable change for Qwen2.5-7B-Instruct.] which we expect not to be relevant to any user prompt.

== Notation

Let the token sequence be
$ x = (x_1, dots.h, x_r, dots.h, x_R, dots.h, x_u, dots.h, x_U, dots.h, x_ell, dots.h, x_L) $
where $(x_r, dots.h, x_R)$ is the rule being enforced, $(x_u, dots.h, x_U)$ is the user prompt, and $(x_ell, dots.h, x_L)$ is the output
(excluding any tokens from the chat template).

Our definition will assume several choices, which will be described in the experiment setup:
- a *baseline* $underline(x)$ used to compute integrated gradients
- a *null rule* sequence $(x'_r, dots.h, x'_R)$, and the corresponding $x'$ defined by substituting this sequence for $(x_r, dots.h, x_R)$ in $x$
- a positive integer $j <= L - ell$ of output tokens to consider

We will work primarily in the embedding space to allow linear combinations.
We let $e$, $underline(e)$ and $e'$ refer to the images of each of these sequences under the embedding map.

== Definitions

We use the log-likelihood of the first $j$ output token embeddings as a score function:

$ F(e) = sum_(t=ell)^(ell+j-1) log p_theta (e_t divides e) $

We define the Integrated Gradient of $F$ with respect to the $i$th token as

$ op("IG")_(i)(x) = (e_i - underline(e)_i) dot.circle integral_0^1(partial F(underline(e) + alpha (e - underline(e)))) / (partial e_i) d alpha $

As usual, we approximate the integral with a Riemann sum over $n$ steps, with $n$ chosen experimentally.

This is a vector in the embedding space, so we define the scalar
$a_i = bold(1)^top op("IG")_(i)(x)$ by summing over the embedding dimensions,
which gives the sequence $a = (a_(u), dots.h, a_U)$ of gradient attributions on each token in the user prompt.
Similarly, we define $a'$ using the null-ruled $x'$ in place of $x$.

Finally, we define the *attribution distance* with output length $j$ as
$ op("AD")(x) = norm( a - a')_2 $
furthermore, we define the *$k$-smoothed attribution distance* as
$ op("AD")^((k))(x) = norm(macron(a)^((k)) - overline(a')^((k)))_2 $
where $macron(a)^((k))$ is the rolling average of $a$ with window size $k$.

= Experiment Design

In order to test rule violation detection in the presence of prompt injection attacks given the definitions above, we require:
- A model that has been post-trained to follow system instructions over user instructions
- A set of system prompt rules which the model can follow, but won't follow if omitted (i.e. they cannot simply reinforce other tendencies post-trained into the model, such as not producing harmful content)
- A set of malicious prompts that interact with the rules
- A set of benign prompts that do not interact with the rules
- A set of prompt injection attacks

== Model Selection

Model selection is driven by several criteria:
- Instruction-following ability
- System/user prompt distinction
- Limitations of available hardware

In order to run on RTX 4090 GPUs with the maximum available VRAM of 24GB, the practical model size is limited to ~10B parameters in FP16 precision.
Many small model families such as Gemma, Mistral and Qwen2 were not post-trained with distinct system roles.
Experimentation with models smaller than 3B parameters found they were unable to enforce most or all of the rules tested.
We chose to focus on the popular Qwen and Llama families of models, testing:
- Llama-3.1-8B-Instruct @meta2024llama3 @meta2024llama31card 
- Llama-3.2-3B-Instruct @meta2024llama32 @meta2024llama32card
- Qwen2.5-7B-Instruct @qwen2024v25
- Qwen3-8B @qwen2025v3 (in non-thinking mode)

== Prompts

Since our detection method only looks at the first $j$ tokens for some small $j$, we focus on rules that clearly affect the first few tokens of output.
A natural class of system prompts to use for this take the form `[general preamble]. If [rule], then reply "[refusal]"`
or grammatically equivalent. We created a dataset of variations of this prompt format and applicable rules with the help of GPT-4o,
which can be found in Appendix 1, Table 4.
We used "Unable" as the refusal string, which is a single token when it appears at the beginning of the assistant response portion
of the chat template for all 4 test models.

Benign prompts were selected from a previously published dataset of benign and malicious prompts @ivry2025sentinel.
Separately, a hand-crafted list of 60 "barely benign" prompts was prepared to evaluate the method's robustness,
which differ from malicious prompts by the addition of a few tokens.
Malicious prompts needed to be tailored for each rule, so we created a new dataset with suggestions generated by GPT-4o.

For each model and rule, we tested the ability the model to refuse our "malicious" test inputs when given the rule but allow them when given the corresponding null rule.
For each model, we only test rules which refuse with at least 50% probability with the rule, and with at most 10% probability with the null rule.
For "barely benign" prompts, we only test those which are refused by the model being evaluated with at most 10% probability and which have malicious variants refused with at least 50% probability.

These new datasets and their refusal probabilities are available in our public repository.

== Prompt Injection Attacks

Most prompt injections attacks are sourced from prior research.
Adversarial suffixes can be generated via gradient-based search techniques and have been shown to work well even against models other than the original
target model, first in _Universal and Transferable Adversarial Attacks on Aligned Language Models_ @zou2023universal.
We use several of the adversarial suffixes first introduced in the associated _llm-attacks_ GitHub repository, which we refer to as "LLM-Attacks Suffix {1,2,3}".
We also use well-known types of attack such as faking a completion before the malicious prompt ("Completion") and instructing the model to ignore
previous instructions ("Ignore") as described in _StruQ: Defending Against Prompt Injection with Structured Queries_ @Chen2025StruQ,
with modifications where necessary to use them in contexts where a long-form text output is expected rather than a yes/no answer.
The "Escape-Separation" attack has been modified to start with `.` since the Llama 3 family prompt templates assume leading newlines have been stripped,
and several variations of it and "Escape-Deletion" are tested with different numbers of newlines or backspaces respectively.
Additionally, we use several automatically generated prompts introduced in _StruQ_, which we refer to as "StruQ Suffix {1,2}" and "StruQ TAP 1".
An additional novel "Superuser" attack was also included in the test.
The full text of each attack is included in Appendix 1, and the effectiveness of each attack is examined in Appendix 2.

== Baseline and Null Rules

Integrated gradients are defined relative to a baseline embedding $underline(e)$.
In principle this can be any length $L$ sequence of vectors in the embedding space, but in practice the behavior of the network far from the images of actual token
sequences is very noisy, making it extremely difficult and expensive to accurately approximate the integral with a Riemann sum.
We define $underline(x)$ as the sequence obtained by replacing $(x_u, dots.h, x_U)$ and $(x_ell, dots.h, x_L)$ with `_`.
Zero and random baselines were tested with Llama-3.2-3B-Instruct but Riemann sum estimates of $op("IG")_(i)(x)$ did not begin to converge even at $n=2048$.
Other "empty" tokens such as `.`, `<|begin_of_text|>` or whitespace tokens converged more slowly than `_`.

Null rules were constructed to avoid refusing any of the malicious or benign prompts.
To avoid any positional effects, they were chosen to have the same token length as the rules being tested.
In most cases, the null rule was `they request [N] flowers`  where $N$ is a sequence of nines such that the
token length matches the original rule (see Appendix 1 for exceptions).

== Responses

Responses were sampled for each unique set of inputs using gradually increasing temperatures and filtered to remove refusals until 3 distinct responses
were obtained (5 for the smaller dataset of "Barely Benign" prompts).
There was a notable tendency for models to refuse with "I won't" or "I can't" rather than "Unable" as directed in the system prompt,
likely due to other post-training, and these were also filtered out. We also consider "I am not sentient" to be a refusal for the inputs specifically
related to sentience, and we exclude these inputs for Qwen3-8B as we were unable to generate any responses other than "I am not sentient" and "Unable",
likely indicating separate post-training for this class of question.

This filtering leads us to use $j>=3$ since "I can't" requires 3 tokens to distinguish from "I can".
After initial investigation of values between $3$ and $10$ with Llama-3.2-3B-Instruct, we restricted our focus to a $j$ value of 3.

== Convergence

The number of steps used to approximate the integral in the Integrated Gradients was validated by comparing the result at $n$ and $2n$ steps
for each model and each value of $j$, using 1 benign and 1 malicious prompt.
In every case $n$ was increased by $64$ until the Euclidean distance between the two, normalized by their combined norms, fell under $0.05$.
This occurred at $n=192$ for Llama models, $n=256$ for Qwen3-8B and $n=512$ for Qwen2.5-7B-Instruct.

= Results and Analysis

== Detecting Successful Attacks

To evaluate how well $op("AD")$ discriminates between malicious prompts which successfully bypass the rule and benign prompts,
we restrict our attention to the "successful" malicious prompts with $p("Unable") < 0.5$ and compute the
average precision of a binary classifier using $op("AD")$.
Since system prompts (and hence rules) are generally fixed in deployed systems, we baseline each rule
against the benign prompts and shift and scale the score distribution so that it is centered at 0 with standard deviation 1.

To avoid Simpson's paradox, we weight each sample so that the positive samples
(i.e. successful malicious prompts) for each rule have the same total weight and do the same for negative samples.
This results in a chance level slightly below $0.5$ as some rules have no positive samples.
We evaluate both $op("AD")$ and the smoothed $op("AD")^((2))$, which performs slightly better on 3 out of 4 models.
Higher degrees of smoothing do not perform better.

#let rows = csv("tables/attribution_distance_average_precision.csv").slice(1)
#let rows = rows.map(r => (
  [#r.at(0)],
  [#int(float(r.at(1)))],
  [#int(float(r.at(2)))],
  [#fmt(r.at(3))],
  [#fmt(r.at(4))],
  [#fmt(r.at(5))],
))
#figure(
  caption: [Average Precision per model for $op("AD")$ and $op("AD")^((2))$.],
  block[
    #table(
      columns: (auto, 3em, 3em, 5em, 6em, 7em),
      align: (left, right, right, right, right, right),
      table.header[*Model*][*N*][*N Pos*][*Chance Level*][*$"AP"("AD")$*][*$"AP"("AD"^((2)))$*],
      ..rows.flatten(),
    )
  ]
)

#figure(
  image("figures/precision_recall.png", width: 120%),
  caption: [Precision-Recall Curves for $op("AD")$ and $op("AD")^((2))$.]
)

#let rows = csv("tables/attribution_distance_average_precision.csv").slice(1)
#let rows = rows.map(r => (
  [#r.at(0)],
  [#fmt(r.at(6))],
  [#fmt(r.at(7))],
  [#fmt(r.at(8))],
))
#figure(
  caption: [Recall using $op("AD")^((2))$ as a classifier at various precision thresholds.],
  block[
    #table(
      columns: (auto, 8em, 8em, 8em),
      align: (left, right, right, right),
      table.header[*Model*][*Recall \@ 90%*][*Recall \@ 95%*][*Recall \@ 99%*],
      ..rows.flatten(),
    )
  ]
)

These results show that $op("AD")^((2))$ is a moderately effective classifier and can catch a modest fraction of successful attacks with
a very low false positive rate, although it performs better for the Llama models than the Qwen models.

== Robustness

Many detection techniques have high false positive rates when faced with benign prompts that are similar to malicious prompts.
For our method, the most obvious candidate for false positives is prompts which would be malicious without key tokens such as "not",
which are similar to prompt injections in that they are a set of additional tokens which cause the rule not to be enforced.
Our hypothesis was that, since these tokens also change the output significantly in the absence of the rule, the Integrated Gradient
associated with these tokens will be similarly large and positive with or without the rule.

To confirm this, we use $op("AD")^((2))$ with the same adjustments and thresholds computed in the previous section
and compute the false positive rate for the "barely benign" prompts at various precision thresholds.
This was evaluated by computing $op("AD")^((2))$ for the "barely benign" prompts after filtering as described in section 4.2,
then compute the false positive rate of the classifier in the previous section using the thresholds for 90%, 95% and 99% precision.

#let rows = csv("tables/robustness_check.csv").slice(1)
#let rows = rows.map(r => (
  [#r.at(0)],
  [#int(float(r.at(1)))],
  [#fmt(r.at(2))],
  [#fmt(r.at(3))],
  [#fmt(r.at(4))],
))
#figure(
  caption: [False positive rate on "barely benign" prompts using the thresholds for 90%, 95% and 99% precision on the original dataset.],
  block[
    #table(
      columns: (auto, 3em, 7em, 7em, 7em),
      align: (left, left, right, right, right),
      table.header[*Model*][*N*][*FPR \@ 90%*][*FPR \@ 95%*][*FPR \@ 99%*],
      ..vmerge(rows),
    )
  ]
)

Comparing these to the recall values in Table 2, we can see that "barely benign" prompts are less likely to be classified as malicious than
the successful attacks examined in the previous section, indicating that the classifier remains somewhat effective.
However, with the exception of Qwen2.5-7B-Instruct, they are higher than we would expect for prompts similar to the original dataset
(roughly $0.1$, $0.05$ and $0.01$ respectively), indicating some degree of confusion.

= Limitations and Future Work

On its own, this method is both more expensive and worse than fine-tuning based methods.
Furthermore, it has the following limitations:
- It does not allow for post-processing of LLM output (or at least such post-processing must be differentiable)---e.g. it will not work for an LLM prompted to output a simple pass/fail
- Rule violations must be apparent in the first few tokens

However, because this method does not rely on any training data, it should be complementary to any fine-tuning method,
allowing the combined detector to perform better.

Our analysis assumes that classifiers are calibrated for the system prompt, which complicates the process of deploying system prompt updates.
Selecting a threshold independent of system prompt is possible but will decrease accuracy.

Practical applications may also be limited by compute and VRAM requirements.
Computing the Riemann sum with $n$ steps costs slightly more than generating $n$ tokens, and this method requires doing so twice per prompt.
Some speedup could be realized by using a smaller $n$ at a small cost in accuracy.
More problematically, the additional VRAM required is non-trivial for longer prompts,
and running in FP16 uses multiple times the VRAM of common 4 and 8-bit quantizations.
Future work should explore the feasibility of this method with lower-precision quantizations and other optimizations.

The choice of baseline $underline(e)$ is very simplistic and could likely be optimized.
This appears to have been a particularly poor choice for Qwen2.5-7B-Instruct as it took twice as long as any other model to converge acceptably,
which may explain why the method performed significantly worse on this model than on any other.
It also presents a performance penalty, since $norm(e - underline(e))_2$ will grow with the embedding dimension $d$ asymptotic to $sqrt(d)$
and thus require more steps to approximate with a Riemann sum.

For the rules analyzed here, $p("Unable")$ would compete with $"AD"$ as a classifier.
The attacks analyzed here are also relatively simple and not targeted at the specific rules being tested, and could be detected by substituting
rules which demand returning "Unable" in all cases and checking whether this is followed.
In principle, $"AD"$ should generalize to more complex classes of rules and attacks for which there is no current alternative,
but verifying this will require more complicated test data and analysis, and potentially can only be tested with larger models.
#pagebreak(weak: true)

#bibliography("paper.bib", style: "ieee")

#pagebreak(weak: true)

#counter(heading).update(0)    // restart the chapter counter
#show heading.where(level: 1): set heading(
  numbering: n => "Appendix " + str(n) + "."  // prints “Appendix 1.”, “Appendix 2.”, …
)
#show figure.where(kind: table): set block(breakable: true)

= Prompts & Attacks

All system prompts were assembled by creating a system prompt template to enforce that rule and then rendering one or more rules into this template.
User inputs were used verbatim as user prompts except for the email system prompt template (where they were prefixed with `Email: `), the tutoring template
(where they were prefixed with `Question: `) and the fact-checking template (where they were prefixed with `Query: `).

#let rows = csv("templates_and_rules.csv").slice(1)
#let rows = rows.map(r => (
  [#raw(r.at(0))],
  [#raw(r.at(2))],
))
#figure(
  caption: [System prompts and rules.],
  block[
    #table(
      columns: (auto, auto),
      align: (left, left),
      table.header[*System Prompt Template*][*Rule*],
      ..vmerge(rows),
    )
  ]
)

Except as noted in Table 6 below, null rules were constructed by repeating either `9` (for Qwen models) or `999` (for Llama models) in the string
`they request [N] flowers`. It was not necessary to construct different exceptions for Qwen and Llama since these examples match the original
rule token lengths in both.

#let rows = (
  ("the email looks like spam", "the email is from mars"),
  ("the email asks you to forward other emails to the sender", "the email asks you to do 1 handed handstands"),
  ("they request financial advice", "they request one flower"),
  ("they request medical advice", "they request one flower"),
)
#figure(
  caption: [Exceptional null rules.],
  block[
    #table(
      columns: (auto, auto),
      align: (left, left),
      table.header[*Rule*][*Null Rule*],
      ..rows.flatten(),
    )
  ]
)

All attacks are listed in Table 6 below in Python f-string format, with `prompt` and `refusal` to be interpolated.
The "Escape-{Separation,Deletion}-[N]" attacks use $N$ copies of `\n` or `\b` respectively and are truncated for readability.
Note that Python f-strings will replace `{{` with `{` and `}}` with `}`,
and that we treat `\b` as the literal 2-character string but `\n` as a newline.

#let rows = csv("attacks.csv").slice(1)
#let rows = rows.map(r => (
  [#r.at(0)],
  [#raw(
    if r.at(0).starts-with("Escape-Separation") {
      r.at(1).slice(0, 3) + "…" + r.at(1).slice(-10)
    } else if r.at(0).starts-with("Escape-Deletion") {
      r.at(1).slice(0, 2) + "…" + r.at(1).slice(-11)
    } else {
      r.at(1)
    }
  )]
))
#figure(
  caption: [Prompt injection attacks in Python f-string format.],
  block[
    #table(
      columns: (auto, auto),
      align: (left, left),
      table.header[*Name*][*Attack Template*],
      ..rows.flatten(),
    )
  ]
)

= Attack Success Rates

Not all attacks are effective against all models.
To evaluate effectiveness, we first baseline $p("Unable")$ for malicious prompts on each model, and then define $Delta p("Unable")$
for each (model, rule, prompt, attack) tuple by subtracting $p("Unable")$ with the attack applied.
Positive values indicate the attack made refusal less likely.

We examine $Delta p("Unable")$ per model and attack by computing statistics per-rule and reporting its macro-average (equal weight per rule).
Confidence intervals are computed using BCa @efron1987bca (cluster bootstrap over rules) with the macro-average recomputed on each resample.
The attacks with an average $Delta p("Unable") > 0$ with at least 97.5% confidence are listed in Table 6.
Note $N$ varies slightly within the same model because we are not always able to sample 3 distinct responses for all attacks.

#let rows = csv("tables/delta_p_refusal.csv").slice(1)
#let rows = rows.map(r => (
  [#r.at(0)],
  [#r.at(1)],
  [#int(float(r.at(2)))],
  [#fmt(r.at(3))],
  [#fmt(r.at(4)) -- #fmt(r.at(5))]
))
#figure(
  caption: [Significantly effective attacks on each model.],
  block[
    #table(
      columns: (auto, 8em, 2.5em, 7em, 6.5em),
      align: (left, left, right, right, right),
      table.header[*Model*][*Attack*][*N*][*$Delta p("Unable")$*][*95% CI*],
      ..vmerge(rows),
    )
  ]
)

The Llama models are vulnerable to a much larger subset of the attacks tested than the Qwen models, which may limit the applicability
of our analysis to the Qwen models.

= Mechanistic Validation

To confirm the intuition behind our definition of $op("AD")$, specifically that the Integrated Gradients will be higher over the tokens in the attack
in $a$ than in $a'$, we define the *attack attribution delta* $op("AAD")(x)$ as the sum of $a - a'$ over these tokens.

In order to study only the successful prompt injection attacks, we limit our attention to the types of attack that significantly outperformed
naive malicious prompting (i.e. those in Table 7), and further to rows where the attack decreased $p("Unable")$.
We compute the frequency with which $op("AAD") > 0$ per (rule, attack) pair and report the macro-average in Table 8.
Confidence intervals are again computed using BCa, this time clustering by (rule, attack) pair.

#let rows = csv("tables/attack_attribution_delta.csv").slice(1)
#let rows = rows.map(r => (
  [#r.at(0)],
  [#int(float(r.at(1)))],
  [#fmt(r.at(2))],
  [#fmt(r.at(3)) -- #fmt(r.at(4))]
))
#figure(
  caption: [Frequency with which $"AAD" > 0$ for effective attacks, per model.],
  block[
    #table(
      columns: (auto, 3em, 8em, 7em),
      align: (left, left, right, right),
      table.header[*Model*][*N*][*$p("AAD" > 0)$*][*95% CI*],
      ..vmerge(rows),
    )
  ]
)

This provides weak confirmation of our intuition---we can be confident that $op("AAD") > 0$ in the majority of cases for all models.
However, it also suggests an upper limit on how effective our technique may be, which may explain the poor performance of the classifier
in the high recall region which can be observed in Figure 1.
