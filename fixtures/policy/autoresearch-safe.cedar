// autoresearch-safe: test-vector policy for agent-governance-testvectors.
//
// Evaluates tool calls typical of a research / development agent.
// Covers four cases: allow Read, allow safe Bash, deny destructive Bash,
// deny unscoped Write.

// Allow read-oriented tools.
permit (
    principal,
    action in [Action::"Read", Action::"Glob", Action::"Grep", Action::"WebSearch"],
    resource
);

// Allow Bash for a safe command list only.
permit (
    principal,
    action == Action::"Bash",
    resource
) when {
    context.command_pattern in ["git", "npm", "ls", "cat", "pwd", "echo", "node", "python"]
};

// Deny destructive Bash regardless of any permit.
// Cedar forbid is authoritative.
forbid (
    principal,
    action == Action::"Bash",
    resource
) when {
    context.command_pattern in ["rm -rf", "dd", "mkfs", "shred"]
};

// Writes must be within the project directory.
permit (
    principal,
    action in [Action::"Write", Action::"Edit"],
    resource
) when {
    context.path_starts_with == "./"
};
