<?php

namespace SecurityAnalyzer\Core;

use PhpParser\Error;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class ASTParser
{
    private $parser;
    private $traverser;

    public function __construct()
    {
        $this->parser = new ParserFactory()->create(ParserFactory::PREFER_PHP7);
        $this->traverser = new NodeTraverser();
        $this->traverser->addVisitor(new NameResolver());
    }

    /**
     *
     *
     * @param string $filePath
     * @return array|null
     */
    public function parseFile(string $filePath): ?array
    {
        if (!file_exists($filePath)) {
            return null;
        }

        $code = file_get_contents($filePath);
        return $this->parseCode($code);
    }

    /**
     *
     *
     * @param string $code
     * @return array|null
     */
    public function parseCode(string $code): ?array
    {
        try {
            return $this->parser->parse($code);
        } catch (Error $e) {
            return null;
        }
    }

    /**
     *
     *
     * @param array $ast
     * @param array $dangerousFunctions
     * @return array
     */
    public function findDangerousFunctionCalls(
        array $ast,
        array $dangerousFunctions,
    ): array {
        $visitor = new class ($dangerousFunctions) extends NodeVisitorAbstract {
            private $dangerousFunctions;
            private $findings = [];

            public function __construct(array $dangerousFunctions)
            {
                $this->dangerousFunctions = $dangerousFunctions;
            }

            public function enterNode(Node $node)
            {
                if ($node instanceof Node\Expr\FuncCall) {
                    $funcName = $this->getFunctionName($node);

                    if (in_array($funcName, $this->dangerousFunctions)) {
                        $this->findings[] = [
                            "function" => $funcName,
                            "line" => $node->getLine(),
                            "args" => $this->getArguments($node),
                            "has_user_input" => $this->hasUserInput($node),
                        ];
                    }
                }
                return null;
            }

            private function getFunctionName(Node\Expr\FuncCall $node): string
            {
                if ($node->name instanceof Node\Name) {
                    return $node->name->toString();
                }
                return "";
            }

            private function getArguments(Node\Expr\FuncCall $node): array
            {
                $args = [];
                foreach ($node->args as $arg) {
                    $args[] = $this->nodeToString($arg->value);
                }
                return $args;
            }

            private function hasUserInput(Node\Expr\FuncCall $node): bool
            {
                foreach ($node->args as $arg) {
                    if ($this->containsUserInput($arg->value)) {
                        return true;
                    }
                }
                return false;
            }

            private function containsUserInput(Node $node): bool
            {
                if ($node instanceof Node\Expr\ArrayDimFetch) {
                    if ($node->var instanceof Node\Expr\Variable) {
                        $varName = $node->var->name;
                        if (
                            in_array($varName, [
                                "_GET",
                                "_POST",
                                "_REQUEST",
                                "_COOKIE",
                                "_SERVER",
                            ])
                        ) {
                            return true;
                        }
                    }
                }

                if ($node instanceof Node\Expr\StaticCall) {
                    if (
                        $node->class instanceof Node\Name &&
                        $node->class->toString() === "Request"
                    ) {
                        return true;
                    }
                }

                foreach ($node->getSubNodeNames() as $name) {
                    $subNode = $node->$name;
                    if ($subNode instanceof Node) {
                        if ($this->containsUserInput($subNode)) {
                            return true;
                        }
                    } elseif (is_array($subNode)) {
                        foreach ($subNode as $item) {
                            if (
                                $item instanceof Node &&
                                $this->containsUserInput($item)
                            ) {
                                return true;
                            }
                        }
                    }
                }

                return false;
            }

            private function nodeToString(Node $node): string
            {
                if ($node instanceof Node\Scalar\String_) {
                    return $node->value;
                }
                if ($node instanceof Node\Expr\Variable) {
                    return '$' . $node->name;
                }
                return get_class($node);
            }

            public function getFindings(): array
            {
                return $this->findings;
            }
        };

        $traverser = new NodeTraverser();
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $visitor->getFindings();
    }

    /**
     *
     *
     * @param array $ast
     * @return array
     */
    public function findSqlInjectionVulnerabilities(array $ast): array
    {
        $visitor = new class extends NodeVisitorAbstract {
            private $findings = [];

            public function enterNode(Node $node)
            {
                if ($node instanceof Node\Expr\StaticCall) {
                    if (
                        $this->isDbRawCall($node) &&
                        $this->hasUserInput($node)
                    ) {
                        $this->findings[] = [
                            "type" => "DB::raw with user input",
                            "line" => $node->getLine(),
                            "severity" => "CRITICAL",
                        ];
                    }
                }

                if ($node instanceof Node\Expr\MethodCall) {
                    $methodName = $this->getMethodName($node);
                    if (
                        in_array($methodName, [
                            "whereRaw",
                            "selectRaw",
                            "havingRaw",
                            "orderByRaw",
                        ])
                    ) {
                        if ($this->hasUserInput($node)) {
                            $this->findings[] = [
                                "type" => "{$methodName} with user input",
                                "line" => $node->getLine(),
                                "severity" => "CRITICAL",
                            ];
                        }
                    }
                }

                return null;
            }

            private function isDbRawCall(Node\Expr\StaticCall $node): bool
            {
                if ($node->class instanceof Node\Name) {
                    $className = $node->class->toString();
                    if (
                        $className === "DB" &&
                        $node->name instanceof Node\Identifier
                    ) {
                        return $node->name->name === "raw";
                    }
                }
                return false;
            }

            private function getMethodName(Node\Expr\MethodCall $node): string
            {
                if ($node->name instanceof Node\Identifier) {
                    return $node->name->name;
                }
                return "";
            }

            private function hasUserInput(Node $node): bool
            {
                foreach ($node->args ?? [] as $arg) {
                    if ($this->containsUserInput($arg->value)) {
                        return true;
                    }
                }
                return false;
            }

            private function containsUserInput(Node $node): bool
            {
                if ($node instanceof Node\Expr\ArrayDimFetch) {
                    if ($node->var instanceof Node\Expr\Variable) {
                        if (
                            in_array($node->var->name, [
                                "_GET",
                                "_POST",
                                "_REQUEST",
                                "_COOKIE",
                            ])
                        ) {
                            return true;
                        }
                    }
                }

                if ($node instanceof Node\Expr\StaticCall) {
                    if (
                        $node->class instanceof Node\Name &&
                        in_array($node->class->toString(), [
                            "Request",
                            "Illuminate\\Http\\Request",
                        ])
                    ) {
                        return true;
                    }
                }

                if ($node instanceof Node\Expr\MethodCall) {
                    if (
                        $node->var instanceof Node\Expr\Variable &&
                        $node->var->name === "request"
                    ) {
                        return true;
                    }
                }

                foreach ($node->getSubNodeNames() as $name) {
                    $subNode = $node->$name;
                    if (
                        $subNode instanceof Node &&
                        $this->containsUserInput($subNode)
                    ) {
                        return true;
                    } elseif (is_array($subNode)) {
                        foreach ($subNode as $item) {
                            if (
                                $item instanceof Node &&
                                $this->containsUserInput($item)
                            ) {
                                return true;
                            }
                        }
                    }
                }

                return false;
            }

            public function getFindings(): array
            {
                return $this->findings;
            }
        };

        $traverser = new NodeTraverser();
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $visitor->getFindings();
    }

    /**
     *
     *
     * @param array $ast
     * @return array
     */
    public function findXssVulnerabilities(array $ast): array
    {
        $visitor = new class extends NodeVisitorAbstract {
            private $findings = [];

            public function enterNode(Node $node)
            {
                // Check for echo with user input
                if ($node instanceof Node\Stmt\Echo_) {
                    foreach ($node->exprs as $expr) {
                        if ($this->hasUnescapedUserInput($expr)) {
                            $this->findings[] = [
                                "type" => "Unescaped echo with user input",
                                "line" => $node->getLine(),
                                "severity" => "HIGH",
                            ];
                        }
                    }
                }

                return null;
            }

            private function hasUnescapedUserInput(Node $node): bool
            {
                if ($this->isUserInput($node)) {
                    return true;
                }
                if ($node instanceof Node\Expr\BinaryOp\Concat) {
                    return $this->hasUnescapedUserInput($node->left) ||
                        $this->hasUnescapedUserInput($node->right);
                }

                return false;
            }

            private function isUserInput(Node $node): bool
            {
                if ($node instanceof Node\Expr\ArrayDimFetch) {
                    if ($node->var instanceof Node\Expr\Variable) {
                        return in_array($node->var->name, [
                            "_GET",
                            "_POST",
                            "_REQUEST",
                            "_COOKIE",
                        ]);
                    }
                }

                if ($node instanceof Node\Expr\StaticCall) {
                    if (
                        $node->class instanceof Node\Name &&
                        $node->class->toString() === "Request"
                    ) {
                        return true;
                    }
                }

                return false;
            }

            public function getFindings(): array
            {
                return $this->findings;
            }
        };

        $traverser = new NodeTraverser();
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $visitor->getFindings();
    }

    /**
     *
     *
     * @param array $ast
     * @return array
     */
    public function findMassAssignmentVulnerabilities(array $ast): array
    {
        $visitor = new class extends NodeVisitorAbstract {
            private $findings = [];
            private $currentClass = null;

            public function enterNode(Node $node)
            {
                if ($node instanceof Node\Stmt\Class_) {
                    $this->currentClass = $node->name->toString();
                    $this->checkMassAssignment($node);
                }
                return null;
            }

            private function checkMassAssignment(Node\Stmt\Class_ $class)
            {
                $hasFillable = false;
                $hasGuarded = false;
                $fillableEmpty = false;
                $guardedEmpty = false;

                foreach ($class->stmts as $stmt) {
                    if ($stmt instanceof Node\Stmt\Property) {
                        foreach ($stmt->props as $prop) {
                            if ($prop->name->toString() === "fillable") {
                                $hasFillable = true;
                                if (
                                    $prop->default instanceof
                                        Node\Expr\Array_ &&
                                    empty($prop->default->items)
                                ) {
                                    $fillableEmpty = true;
                                }
                            }
                            if ($prop->name->toString() === "guarded") {
                                $hasGuarded = true;
                                if (
                                    $prop->default instanceof
                                        Node\Expr\Array_ &&
                                    empty($prop->default->items)
                                ) {
                                    $guardedEmpty = true;
                                }
                            }
                        }
                    }
                }

                if (!$hasFillable && !$hasGuarded) {
                    $this->findings[] = [
                        "type" => 'Missing $fillable or $guarded',
                        "class" => $this->currentClass,
                        "line" => $class->getLine(),
                        "severity" => "HIGH",
                    ];
                } elseif ($guardedEmpty) {
                    $this->findings[] = [
                        "type" => 'Empty $guarded array (all fields fillable)',
                        "class" => $this->currentClass,
                        "line" => $class->getLine(),
                        "severity" => "CRITICAL",
                    ];
                }
            }

            public function getFindings(): array
            {
                return $this->findings;
            }
        };

        $traverser = new NodeTraverser();
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $visitor->getFindings();
    }
}
