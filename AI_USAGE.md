# AI Usage Disclosure

## Tools used
ChatGPT (Codex coding agent).

## What I used them for
Reviewed the assignment specifications, implemented the Assignment A pipeline and focused tests, and drafted the setup, design, and submission documentation.

## What I wrote or decided myself
The solution was produced with AI assistance in this session, so I cannot claim unaided authorship of its code. The implementation choices are documented in `SUBMISSION.md`; the candidate should review, understand, and be prepared to explain each one before submitting.

## Where the AI was wrong or unhelpful
An early implementation counted unknown dispositions before checking whether the event could be linked. Reviewing the assignment's explicit processing order exposed the mismatch; the pipeline was changed to quarantine first and count unknown dispositions after a link is available.

## How I verified AI-generated code
Ran the six focused pytest cases and generated/ingested both provided seed-42 small-data drops, then produced and inspected the contract report files. A full independent oracle diff and large-scale performance run remain to be done.
