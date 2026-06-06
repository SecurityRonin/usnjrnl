# LinkedIn Posts

## Post 1: The Contrarian ("Coders vs Engineers")

Most software engineers aren't engineers. They're translators.

For 40 years, the job has been: read a spec, translate it into code. We called it "software engineering" but it was closer to transcription with a CS degree.

I'm not being dismissive — I did it too. We all did. Translation was the bottleneck, so translation was the job.

AI just removed that bottleneck.

And something interesting happened: the people who actually understand *what* to build and *why* — the ones with deep domain knowledge, systems thinking, and taste — suddenly became 10x more productive than everyone else.

Here's a concrete example. I led incident response at HSBC. I've spent 15+ years in digital forensics — reconstructing attacker timelines from NTFS artifacts, recovering evidence of data exfiltration, detecting anti-forensics tampering.

Last Sunday I started building a forensic analysis tool. By Saturday — 6 days — I had shipped 6 releases: 19,000 lines of Rust, 489 tests, 36 source files. Point it at a 15 GiB disk image. 35 seconds later: 12 investigative questions answered, 12,000+ deleted records recovered from unallocated space, one self-contained HTML report you hand to your incident commander.

I benchmarked it against every major tool in the space. They cover 3-7 out of 27 forensic capabilities. Mine covers 27 out of 27.

Not because AI wrote my code. Because I could finally operate at the speed of my understanding instead of the speed of my typing. The AI didn't know what ghost records are, or how to detect SDelete patterns, or why you process a journal in reverse chronological order to reconstruct directory trees. I did. I just finally had a tool that could keep up.

The discipline that makes this possible isn't "prompt engineering." It's **context engineering** — giving AI precise, structured context so it executes at the level of your expertise, not at the level of a junior dev guessing at requirements.

We've finally put the *engineering* back in software engineering.

#SoftwareEngineering #AI #ContextEngineering #DFIR #CyberSecurity

---

## Post 2: The Story Hook (Exec-friendly)

6 days. 19,000 lines. 489 tests. One person.

When a company gets breached — or an employee exfiltrates data — investigators rely on NTFS journal artifacts to reconstruct what happened. Which files were created, renamed, deleted, and when.

The problem: every existing tool leaves gaps. Incomplete file paths. Missing records. No detection of anti-forensics tampering. Investigators build timelines with holes in them — and holes are where reasonable doubt lives.

I led incident response at HSBC. I've spent 15+ years doing this work. I knew exactly what was missing. I'd been mentally designing this tool for years.

What I lacked was implementation bandwidth. Building a forensic parser that opens E01 images, correlates 4 NTFS artifacts, carves deleted evidence from unallocated disk space, detects ransomware patterns, and generates interactive HTML triage reports — that's months of work for a solo developer.

I started last Sunday. By Saturday I had shipped v0.6 — 6 releases, 27 out of 27 forensic capabilities, 489 tests passing. Point it at a 15 GiB disk image. 35 seconds later: 12 investigative questions answered, 12,000+ deleted records recovered from unallocated space, one self-contained HTML report you hand to your incident commander.

The closest competitor covers 7 out of 27.

The difference wasn't the AI. AI doesn't know forensics. The difference was **context engineering** — the discipline of translating 15 years of incident response experience into structured context that AI can execute against.

This is the shift leaders need to understand:

The cost of translating ideas into code just dropped to zero. The bottleneck is no longer "can we build it?" It's "do we actually understand the problem deeply enough to build the right thing?"

The teams winning right now aren't the ones with the best coders. They're the ones with the deepest domain knowledge — who finally have tools that match their speed of thought.

Context engineering is the new literacy.

#Leadership #AI #ContextEngineering #CyberSecurity #DigitalForensics

---

## Post 3: The Pattern-Interrupt (Short & punchy)

27 out of 27. The next best tool covers 7.

Last Sunday I started building a forensic analysis tool from scratch. By Saturday I had shipped 6 releases.

19,000 lines of Rust. 489 tests. 36 source files. Point it at a 15 GiB disk image. 35 seconds later: 12 investigative questions answered, 12,000+ deleted records recovered from unallocated space, one self-contained HTML report you hand to your incident commander.

100% path resolution. Every competitor has gaps they label "UNKNOWN."

"So you must have a big team."

Just me.

"You must be an exceptionally fast coder."

I'm not. I'm a former HSBC IR Lead who's been doing digital forensics for 15+ years.

That's the whole point.

For 40 years, we called software development "engineering." But most of us were translators — converting mental models into syntax. That was the hard part, so that was the job.

AI made translation free. And now the actual engineering — domain expertise, systems thinking, understanding *what* to build and *why* — is the only thing that matters.

The practice that bridges deep expertise and AI execution is called **context engineering**. Not prompting. Not vibe coding. Disciplined context engineering — the same rigor you'd apply to designing the system itself, applied to how you communicate with AI.

The coders are wondering why AI isn't making them faster.

The engineers never had this problem.

#ContextEngineering #AI #DFIR #SoftwareEngineering #CyberSecurity
