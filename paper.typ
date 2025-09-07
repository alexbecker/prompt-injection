#import "@preview/unequivocal-ams:0.1.2": ams-article
#import "@preview/oxifmt:0.2.1": strfmt
#show: ams-article.with(
  title: text(  // Override for readability in PDF.js
    font: "TeX Gyre Termes",
    weight: 700,
    tracking: 0pt,
  )[Detecting Prompt Injections with Contrastive Per-Token Attributions],
  authors: (( name: "Alex Becker" ),),
  abstract: [
Modern LLMs are often given rules to follow via a trusted system prompt and then fed untrusted user prompts.
However, malicious user prompts are frequently able to bypass these rules using techniques known as prompt injections.
Existing defenses against prompt injection generally depend on fine-tuning models using datasets of known attacks,
making them vulnerable to unknown attacks.
We propose a novel metric for detecting direct prompt injection attacks using per-token attributions rather than fine-tuning.
This metric outperforms existing training-free methods on a majority of models tested and is the first to
require no example attacks to calibrate.
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

If LLMs are to reach their full potential, they will need to handle untrusted input safely and reliably.
Specifically, organizations and individuals deploying LLMs will need to be able to specify what the LLM should and should not do,
and trust that whatever other non-privileged input the LLM is fed by others will not cause it to ignore these instructions.
This is particularly important when deploying LLMs as agents, which must be able to take autonomous actions.

_Prompt injection_---a term coined by Willison in 2022 as an analogy to SQL injections @willison2022
after the first public demonstration against GPT-3 @goodside2022 @cefalu2022 ---refers to a loosely-defined collection of techniques used to
trigger an LLM to ignore or modify instructions provided by the author of an LLM-based agent or application.
The term _jailbreak_ is sometimes used interchangeably, but often refers to a broader class of techniques used to elicit other classes of undesirable behavior
such as providing instructions for law-breaking activities.
We use the term prompt injection here to refer to the aforementioned narrower class.

Most LLMs used in agents and applications have been tuned with reinforcement learning to use a chat template which includes distinct
_system prompt_ and _user prompt_ portions and to prioritize instructions in the system prompt,
and official advice from major labs such as OpenAI is for application and agent authors to provide instructions there @openai2025prompting.
This is conceptually similar to how most SQL libraries allow application authors to specify query templates separately from values which may come from the user.
However, the system prompt/user prompt separation does not offer the same guarantee that proper use of SQL libraries does.

Prompt injection defenses have been developed which have reasonable success in the _indirect prompt injection_ setting,
which assumes inputs are partitioned into trusted instructions and untrusted data.
However, this assumption cannot hold in any situation where prior model outputs (which are tainted by untrusted input)
are expected to provide instructions---which includes reasoning models, multi-turn conversations and agents.
These use cases require us to handle the more general problem of _direct prompt injection_,
creating separate user and system roles and assuming that instructions from the user or from previous LLM output should be
followed unless they conflict with instructions from the system role.
Furthermore, many prompt injection defenses have historically assumed that prompt injection attacks obfuscate instructions that are
objectively malicious, while agent authors expect to be able to enforce system policies (e.g. restrictions on spending money)
which preclude actions that in other contexts may be desirable.

While some work has been done to make models handle conflicts between instructions with different privilege levels,
evaluating the success of this work requires making very subjective judgments.
We instead focus on detecting clear-cut violations of rules agent authors wish an LLM to enforce, leaving
the responsibility on the harness to determine how to handle these rejections (e.g. by automatically rewriting and retrying a query).
This eliminates any ambiguity about what it means for a rule to be enforced, allowing us to ignore malicious prompts which are handled correctly
and focus on distinguishing between benign prompts and successful prompt injections.
While this may appear to be a major restriction, many practical requirements can be realized in this format---for example, the requirement that
a list of transactions balance debits and credits can be converted into the rule "reject attempts to generate a list of transactions that is not balanced".

Since we are interested in causal analysis of prompt injections, we restrict our attention to _successful_ prompt injections.
This means we consider not only the user input but the generated response, since the generated response defines whether the prompt injection is successful.

= Related Work

Broadly speaking, prior work on prompt injection defenses can be divided into detection, model hardening, and capability-based isolation.
We briefly survey these approaches and discuss how applicable they are to our to our scenario.

== Detection

Detection methods tend to work for both direct and indirect prompt injections, at least as benchmarked in the literature,
because the attack methods and objectives typically tested in both settings have high overlap.
However, we will see in our analysis that this does not necessarily transfer when attack objectives are changed to fit the direct prompt injection scenario.

Most defenses leverage off-the-shelf text-classification models.  
An early example is *LLM Guard-v2*, which fine-tunes DeBERTa-v3 on a composite dataset of known attacks and benign prompts
and reports $F_1 approx 0.95$ on its held-out split @llmguardv2.
*Sentinel* fine-tunes a ModernBERT-large classifier on a more diverse corpus, reporting achieving nearly 100% accuracy on older benchmarks
and $F_1 approx 0.98$ on its unseen test set @ivry2025sentinel.
*DataSentinel* achieves similar benchmark results but better robustness against adaptive attacks by formulating detection as a minimax game
against adaptive attackers, alternating gradient-based attack generation with detector training @liu2025datasentinel.

To our knowledge, there is little previous training-free work focused on detecting prompt injections.
*Attention Tracker* experimentally identifies attention heads whose last-token attention drops most when subject to a prompt injection attack.
Averaging attention across these heads to detect prompt injection outperforms Prompt Guard on several common model families and datasets,
but is vulnerable to adversarial methods @hung2025attention.
Although this approach is training-free, it still requires calibration using a small set of known attacks to identify important attention heads.

There is also prior work for using gradients to detect safety policy violations, which is similar to our work though not focused specifically on prompt injections.
*GradSafe* computes the cosine similarity between the gradient of "safety-critical" parameters and a reference vector @xie2024gradsafe.
*Gradient Cuff* considers the gradient of the probability of a refusal response @hu2024gradientcuff-neurips.
*Token Highlighter* builds on this concept by identifying the tokens with the largest such gradient and "soft removing" other tokens by scaling the embeddings
down @hu2025tokenhighlighter.

== Model Hardening

More recent approaches introduce logical separation between the trusted and untrusted inputs in the network and fine-tuning the LLM to treat them differently.
*Structured Queries (StruQ)* adds a dedicated delimiter token that splits a query into `⟨prompt⟩` and `⟨data⟩` channels; fine-tuning with contrastive pairs cuts manual jailbreak success on Llama-7B and Mistral-7B to $<2%$ and significantly reduces the effectiveness of several adversarial methods @Chen2025StruQ.
*SecAlign* builds on this work using a preference-optimization dataset where "secure" completions obey the system prompt and "insecure" ones follow the injected instruction; RLHF on this dataset drives the success rate of six canonical attacks to $<10%$ on Llama-3-8B-Instruct without harming AlpacaEval scores @secalign2025.

Both StruQ and SecAlign focus on indirect prompt injection.
Direct prompt injection hardening was first attempted by OpenAI, which introduced the *Instruction Hierarchy* dataset containing conflicting system,
user and tool content, and fine-tuned GPT-3.5 on it to respect their precedence rules @wallace2024instructionhierarchy.
*Instructional Segment Embedding (ISE)* introduces a four-way segment embedding (`system`, `user`, `data`, `response`)
which handles both direct and indirect prompt injection attacks.
Fine-tuning Llama-2-7B with ISE improves its performance on both the Instruction Hierarchy dataset and StruQ's indirect prompt injection benchmark @ise2025,
but does not achieve parity with SecAlign on indirect prompt injection.

To our knowledge, the only training-free hardening method is *Attention Sharpening*, which builds on the insights of the Attention Tracker detection method
by adjusting attention normalization to prevent what it calls "Attention Slipping" in the critical attention heads @hu2025attentionslipping.

== Capability-based Isolation

Other work has focused on minimizing the harm a successful prompt injection can cause by requiring user approval for any dangerous action.
The *Dual LLM* pattern proposed by Willison in 2023 pipes the output of an "untrusted" assistant model into a second, policy-enforcing model that rewrites or refuses unsafe text @willison2023dualllm. While effective against direct prompt injections, it remains vulnerable if the second model blindly trusts the first model’s output and so can still relay hidden adversarial payloads @camel2025 @willison2025camel.

Google DeepMind’s *CaMeL* (Capabilities for Machine Learning) hardens this idea by isolating untrusted input inside a "Quarantined LLM" that has no tool-calling rights, then passing only a verified, least-privilege representation to a "Privileged LLM". CaMeL solves 67% of tasks on the AgentDojo benchmark with formal security guarantees and addresses the vulnerability found in Dual LLM @camel2025.

= Detection Approach

Our intuition for detecting successful prompt injections is to compare how the user prompt influences the response when the rule is present versus when it is not.
In order to minimize changes in the grammatical structure of the prompt and avoid introducing changes due to the positional encoding,
rather than deleting rules entirely we replace them with specially constructed _null rules_ of the same length#footnote[During the initial analysis
of our experimental data, we noticed that our construction of most null rules did not count tokens correctly for the Qwen tokenizer.
This was corrected and the experiment re-run for the Qwen models, resulting in a small improvement for Qwen3-8B and
no noticeable change for Qwen2.5-7B-Instruct.] which we expect not to be relevant to any user prompt.

We hypothesize that the attack portion of the user prompt will have a large causal impact on the output when the rule is present, but not when the
rule is replaced by the null rule. To detect this, we use Integrated Gradients @sundararajan2017 to attribute changes per-token in the input
and compare the per-token attributions when using the rule versus the null rule.
More precisely, we compute per-token Integrated Gradient attributions for the log-likelihood of the first $j$ output tokens
under the rule and a null rule; our detector is the attribution distance between these two runs.
Integrated Gradient attributions are defined relative to a baseline embedding, which we construct by modifying the input
and then---in order to keep the path from the baseline to the input from straying too far "off manifold"---taking a weighted average with
the input which favors the input.

We introduce some notation to describe this more formally.

== Notation

Let the token sequence be
$ x = (x_1, dots.h, x_r, dots.h, x_R, dots.h, x_u, dots.h, x_U, dots.h, x_ell, dots.h, x_L) $
where $(x_r, dots.h, x_R)$ is the rule being enforced, $(x_u, dots.h, x_U)$ is the user prompt, and $(x_ell, dots.h, x_L)$ is the output
(excluding any tokens from the chat template).

Our definition will assume several choices, which will be described in the experiment setup:
- a *baseline* $underline(x)$ used to compute integrated gradients
- a *null rule* sequence $(x^("null")_r, dots.h, x^("null")_R)$, and the corresponding $x^("null")$ defined by substituting this sequence for $(x_r, dots.h, x_R)$ in $x$
- a positive integer $j <= L - ell$ of output tokens to consider

We will work primarily in the embedding space to allow linear combinations.
We let $e$, $underline(e)$, $e^("null")$ and $underline(e)^("null")$ refer to the images of each of these sequences under the embedding map $E$.

== Formal Definition

We use the log-likelihood of the first $j$ output token embeddings as a score function:

$ F(e) = sum_(t=ell)^(ell+j-1) log p_theta (e_t divides e) $

We define the Integrated Gradient of $F$ with respect to the $i$th token as

$ op("IG")_(i)(x) = (e_i - underline(e)_i) dot.circle integral_0^1(partial F(underline(e) + t (e - underline(e)))) / (partial e_i) d t $

As usual, we approximate the integral with a Riemann sum over $n$ steps, with $n$ chosen experimentally.
The baseline $underline(e)$ is defined as $underline(e) = (1 - alpha) E(x) + alpha E(underline(x))$ where $underline(x)$
is the sequence obtained by replacing $(x_u, dots.h, x_U)$ and $(x_ell, dots.h, x_L)$ with `_`, and $alpha$ is chosen experimentally.

This is a vector in the embedding space, so we aggregate per-token attributions
$a_i = bold(1)^top op("IG")_(i)(x)$ by summing over the embedding dimensions,
which gives the sequence $a = (a_(u), dots.h, a_U)$ of gradient attributions on each token in the user prompt.
Similarly, we define $a^("null")$ using the null-ruled $x^("null")$ in place of $x$.

Finally, we define the *attribution distance* with output length $j$ as
$ op("AD")(x) = norm( a - a^("null"))_2 $

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
- Ability to run on RTX 4090 GPUs

Many small model families such as Gemma, Mistral and Qwen2 were not post-trained with distinct system roles.
Experimentation with models smaller than 3B parameters found they were unable to enforce most or all of the rules tested.
We chose to focus on the popular Qwen and Llama families of models, testing:
- Llama-3.1-8B-Instruct @meta2024llama3 @meta2024llama31card 
- Llama-3.2-3B-Instruct @meta2024llama32 @meta2024llama32card
- Qwen2.5-7B-Instruct @qwen2024v25
- Qwen3-8B @qwen2025v3 (in non-thinking mode)

== System and User Prompts

Since our detection method only looks at the first $j$ tokens for some small $j$, we focus on rules that clearly affect the first few tokens of output.
A natural class of system prompts to use for this take the form `[general preamble]. If [rule], then reply "[refusal]"`
or grammatically equivalent. We created a dataset of variations of this prompt format and applicable rules with the help of GPT-4o,
which can be found in Appendix 1, Table 4.
We used "Unable" as the refusal string, which is a single token when it appears at the beginning of the output portion
of the chat template for all 4 test models#footnote[`Unable` has token ID 17512 for the Llama models and 17075 for the Qwen models.].

Benign prompts were selected from a previously published dataset of benign and malicious prompts @ivry2025sentinel.
Separately, a hand-crafted list of 60 "barely benign" prompts was prepared to evaluate the method's robustness,
which differ from malicious prompts by the addition of a few tokens.
These are similar to prompt injections in that they are a set of additional tokens which cause the rule not to be enforced.
Malicious prompts needed to be tailored for each rule, so we created a new dataset with suggestions generated by GPT-4o.

For each model and rule, we tested the ability the model to refuse our "malicious" test inputs when given the rule but allow them when given the
corresponding null rule.
For each model, we only test rules which refuse with at least 50% probability with the rule, and with at most 10% probability with the null rule.
For "barely benign" prompts, we only test those which are refused by the model being evaluated with at most 10% probability and which have
malicious variants refused with at least 50% probability.

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

== Null Rules

Null rules were constructed to avoid refusing any of the malicious or benign prompts.
To avoid any positional effects, they were chosen to have the same token length as the rules being tested.
In most cases, the null rule was `they request [N] flowers`  where $N$ is a sequence of nines such that the
token length matches the original rule (see Appendix 1 for exceptions).

== Responses

Because we are interested in _successful_ prompt injections, we must include the generated responses in our analysis.
We must use real responses generated by the models being tested for causal attribution to make sense.

Responses were sampled for each unique set of inputs using gradually increasing temperatures and filtered to remove refusals until 3 distinct responses 
were obtained (5 for the smaller dataset of "Barely Benign" prompts).
There was a notable tendency for models to refuse with "I won't" or "I can't" rather than "Unable" as directed in the system prompt,
likely due to other post-training, and these were also filtered out. We also consider "I am not sentient" to be a refusal for the inputs specifically
related to sentience, and we exclude these inputs for Qwen3-8B as we were unable to generate any responses other than "I am not sentient" and "Unable",
likely indicating separate post-training for this class of question.

This filtering leads us to use $j>=3$ since "I can't" requires 3 tokens to distinguish from "I can".
After initial investigation of values between $3$ and $10$ with Llama-3.2-3B-Instruct, we restricted our focus to a $j$ value of 3.

== Baselines and Convergence

Integrated gradients are defined relative to a baseline embedding $underline(e)$.
The rate at which the $n$-step Riemann sum $R_n$ used to approximate $op("IG")(x)$ converges depends on our choice of baseline $underline(e)$,
in particular the length (proportional to $alpha$) of the line between $e$ and $underline(e)$ and how far it strays from the image of token sequences under $E$
where the models are well-behaved.

We validate convergence by comparing the Riemann sums at $n$ and $2n$ steps, specifically the normalized Euclidean distance
$ norm( R_n - R_(2n) )_2 / (norm( R_n )_2 + norm( R_(2n) )_2) $
using a sample of 5 benign and 3 malicious prompts.
For each model, the value of $n$ was increased starting from 32 to 64 and then by adding 64 repeatedly until this normalized distance fell below .01
(or .005 for the smallest model Llama-3.2-3B-Instruct).

Initial testing with Llama-3.2-3B-Instruct motivated the choice of `_` in our definition of $underline(x)$, as $op("IG")(x)$ converged more slowly with
other "empty" tokens such as `.`, `<|begin_of_text|>` or whitespace tokens.
Experiments with Llama-3.2-3B-Instruct show performance improving slightly as $alpha$ increases but capping out at $alpha=.05$ as shown below.

#let rows   = csv("tables/alpha_comparison.csv").slice(1)
#let alphas = rows.map(r => fmt(r.at(0)))
#let ap     = rows.map(r => fmt(r.at(1)))

#figure(
  caption: [Average Precision of $op("AD")$ at various $alpha$ values for Llama-3.2-3B-Instruct.],
  block[
    #table(
      columns: alphas.len() + 1,
      align: right,
      table.header(
        [*$alpha$*], ..alphas.map(a => [#a])
      ),
      [*Average Precision*], ..ap.map(v => [#v])
    )
  ]
)

Conversely, higher values of $alpha$ converge more slowly, with Qwen2.5-7B-Instruct requiring $n=256$ at $alpha=.01$, $n=384$ at $alpha=.05$,
and triggering numerical stability exceptions at $alpha = .1$.

As a result we selected $alpha=.05$ for all further analysis, with $n=32$ for Llama-3.1-8B-Instruct, $n=128$ for Llama-3.2-3B-Instruct, 
$n=384$ for Qwen2.5-7B-Instruct and $n=192$ for Qwen3-8B.

== Comparison with Existing Methods

We chose to compare our performance to 2 SoTA detection models, Sentinel and DataSentinel, as well as the unique training-free detection method Attention Tracker.
Each of these methods produces a numeric score similar to $op("AD")$.

In order to compare Attention Tracker to our results, which use more recent models, we use their public code to select the relevant attention heads.
Heads selected by their "llm" calibration dataset with $sigma = 3$ or $sigma = 4$ as used in their evaluations performed poorly on our evaluations,
so we created a new calibration dataset and tested all positive integer $sigma$ values with nonempty heads and selected the best performing set for each model.
The code for this and the selected heads are available in our fork #link("https://github.com/alexbecker/Attention-Tracker")[github.com/alexbecker/Attention-Tracker].

= Results and Analysis

To evaluate how well each method discriminates between malicious prompts which successfully bypass the rule and benign prompts,
we restrict our attention to the "successful" malicious prompts with $p("Unable") < 0.5$ and compute the
average precision of each method when used as a binary classifier.
Since system prompts (and hence rules) are generally fixed in deployed systems, we baseline each rule
against the benign prompts and shift and scale the per-rule score distributions for $op("AD")$ and Attention Tracker#footnote[
  This was not done for Sentinel because the distribution is tightly clustered at 0 and 1.]
so that the distribution is centered at 0 with standard deviation 1.

To avoid Simpson's paradox, we weight each sample so that the positive samples
(i.e. successful malicious prompts) for each rule have the same total weight and do the same for negative samples.
This results in a chance level of $0.5$ for the Llama models, but $0.481$ for Qwen2.5-7B-Instruct and $0.462$ for Qwen3-8B as some rules have no positive samples.

DataSentinel performed poorly on our dataset, with a FPR of 52.6% on our benign prompts and TPR against the most successful attack families ranging from 45% to 61%,
so was excluded from further analysis. We hypothesize this is due to a lack of non-malicious instruction-following training data.

#let rows = csv("tables/average_precision_comparison.csv").slice(1)
#let rows = rows.map(r => (
  [#r.at(0)],
  [#int(float(r.at(2)))],
  [#fmt(r.at(4))],
  [#fmt(r.at(5))],
  [#fmt(r.at(6))],
  [#fmt(r.at(7))],
))
#figure(
  caption: [Average Precision per model for our metric $op("AD")$, Attention Tracker (using both the original and our recalibrated head selection method), and Sentinel.],
  block[
    #table(
      columns: (auto, 3em, 3.5em, 6em, 6em, 5em),
      align: (left, right, right, right, right, right),
      table.header[*Model*][*N Pos*][*AD*][*Attention Tracker (orig)*][*Attention Tracker (recal)*][*Sentinel*],
      ..rows.flatten(),
    )
  ]
)

Our metric out-performs Attention Tracker for 3 out of 4 models.
Attention Tracker performs extremely well on Completion and Ignore-Completion attacks---which
as shown in Appendix 2, Table 6 are the most frequently successful---but poorly on other attacks#footnote[
  A breakdown by attack type is available in the Jupyter notebook in our GitHub repository.].
We were unable to determine why Attention Tracker performs so poorly for Qwen2.5-7B-Instruct, where it exhibits a similar but much
narrow distribution of scores by attack type.

However, neither method is comparable to the Sentinel fine-tuned detection model. This is not surprising as the attacks tested here
were mostly well-known when Sentinel's dataset was prepared, and the benign prompts were selected from the same test data used to
evaluate Sentinel.

These results include an ablation study of distance metric for the definition of $op("AD")$ and show that the Euclidean distance
outperforms cosine distance for 3 out of 4 models.

To evaluate whether our metric is misled by the "barely benign" prompts, we selected the thresholds for each model that produced
the optimal $F_1$ score and computed the FPR on the "barely benign" dataset at this threshold.

#let rows = csv("tables/robustness_check.csv").slice(1)
#let rows = rows.map(r => (
  [#r.at(0)],
  [#int(float(r.at(1)))],
  [#fmt(r.at(2))],
  [#fmt(r.at(3))],
  [#fmt(r.at(4))],
  [#fmt(r.at(5)) -- #fmt(r.at(6))]
))
#figure(
  caption: [Comparison of FPR on the normal dataset vs. on the "barely benign" dataset using a fixed threshold optimized for $F_1$ against the normal dataset.],
  block[
    #table(
      columns: (auto, 3em, 3.5em, 5em, 5em, 7em),
      align: (left, left, right, right, right, right),
      table.header[*Model*][*N*][*$F_1$*][*Normal Dataset FPR*][*Barely Benign FPR*][*95% CI*],
      ..vmerge(rows),
    )
  ]
)

For 3 out of the 4 models, the FPR does not increase significantly, although a small increase cannot be ruled out due to our small sample size.
The FPR does increase significantly for Qwen3-8B, which is also the worst-performing model.

= Limitations and Future Work

Several limitations make this method impractical for use in production systems.
It is less accurate than fine-tuned detection models.
It is also very expensive to compute---roughly $n times$ the cost of processing all input tokens.
While significant speedups could be realized with a small accuracy trade-off by reducing $n$,
and future work could explore the feasibility of lower-precision quantizations,
it will still be significantly slower and require more VRAM than other methods.
Our analysis assumes that classifiers are calibrated for the system prompt, which complicates the process of deploying system prompt updates.
Selecting a threshold independent of system prompt is possible but will decrease accuracy.

However, this method is still potentially useful in offline or latency-insensitive contexts to screen for novel attacks,
which fine-tuned models cannot be expected to catch.

Several potential avenues of improvement could be explored.
Many alternative loss functions could be substituted in place of the contrastive entropy of the first $j$ tokens in the definition of $op("AD")$.
The choice of baseline $underline(e)$ is also simplistic and could likely be optimized.
This appears to have been a particularly poor choice for the Qwen models, which required more steps to converge,
and this may explain why the method performed worse on these models.

Our analysis is also limited by the datasets we have constructed.
The attacks analyzed are relatively simple and not targeted at the specific rules being tested.
Future work could verify that this method works for attacks designed to evade known-answer detection, or for other more complex classes of attacks.
Since $op("AD")$ is differentiable, standard gradient-based optimization techniques could be used to generate attacks,
which we expect would evade detection and may offer insights about the behavior of $op("AD")$, although the cost may be prohibitive given the
expense of computing $op("AD")$ with gradients.
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

= Distance Ablation

In addition to the $ell_2$ (Euclidean) distance, we tested defining $op("AD")$ using $ell_1$, $ell_infinity$ and cosine distance.
We found Euclidean distance outperforms other $ell_p$ distances for all models and cosine for 3 out of 4 models.
Cosine distance makes less theoretical sense because the magnitude of the attributions matters.

#let rows = csv("tables/attribution_distance_average_precision.csv").slice(1)
#let rows = rows.map(r => (
  [#r.at(0)],
  [#fmt(r.at(4))],
  [#fmt(r.at(5))],
  [#fmt(r.at(6))],
  [#fmt(r.at(7))],
))
#figure(
  caption: [Average Precision of $op("AD")$ per model using various distance functions.],
  block[
    #table(
      columns: (auto, 4em, 4em, 4em, 4em),
      align: (left, right, right, right, right),
      table.header[*Model*][*$op("cos")$*][*$ell_1$*][*$ell_infinity$*][*$ell_2$*],
      ..rows.flatten(),
    )
  ]
)
