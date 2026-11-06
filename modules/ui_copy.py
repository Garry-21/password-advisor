LOSS_FRAMES = {
    "breach": "This exact password has already appeared in {n} known data "
              "breaches — attackers use these lists first, before anything else.",
    "semantic": "Your password reveals {detail}, which anyone who knows you "
                "or finds your public profile could guess in seconds.",
    "syntax": "Its short length and simple structure mean automated cracking "
              "tools could break it in minutes, not years.",
}

NEUTRAL_FRAMES = {
    "breach": "This password appears in {n} known data breaches.",
    "semantic": "This password contains {detail}.",
    "syntax": "This password does not meet the recommended complexity level.",
}

def build_nudge(*args, **kwargs) -> str:
    """
    Builds a personalized nudge string based on the provided findings.
    Accepts:
      - build_nudge("A", findings)
      - build_nudge(findings, variant="A")
      - build_nudge(variant="A", findings=findings)
    """
    variant = "A"
    findings = []

    if len(args) >= 2:
        if isinstance(args[0], (list, tuple)):
            findings, variant = args[0], args[1]
        else:
            variant, findings = args[0], args[1]
    elif len(args) == 1:
        if isinstance(args[0], (list, tuple)):
            findings = args[0]
            variant = kwargs.get("variant", "A")
        else:
            variant = args[0]
            findings = kwargs.get("findings", [])
    else:
        variant = kwargs.get("variant", "A")
        findings = kwargs.get("findings", [])

    if not findings:
        return ""

    frames = LOSS_FRAMES if str(variant).upper() == "A" else NEUTRAL_FRAMES
    sentences = []
    for f in findings:
        if isinstance(f, str):
            sentences.append(f)
            continue
        if not isinstance(f, dict):
            continue
        template = frames.get(f.get("type"))
        if not template:
            continue
        sentences.append(template.format(
            n=f.get("n", "multiple"),
            detail=f.get("detail", "personal information"),
        ))
    return " ".join(sentences)
