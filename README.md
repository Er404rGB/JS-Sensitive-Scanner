

**JS Sensitive Scanner** is a tool for analyzing JavaScript code to find sensitive data such as API keys, tokens, passwords, private keys and other confidential information left in source code. It searches for such data in JavaScript, TypeScript, and JSON files, as well as in connection strings and cookies.

**Search for sensitive data:**

* AWS Access Key ID, Secret Access Key
* Google API Key, Firebase Config Key
* GitHub Token, Slack Token
* JWT tokens
* Stripe Key, Private Keys (PEM)
* Logins and passwords in code
* Database connection strings (MongoDB, MySQL, PostgreSQL and others)
* Use of cookies and localStorage
* Search for high-entropy strings — potential tokens and keys that may be generated or random.

**Detection of unsafe operations:**

* Use of `eval`, `Function`, `localStorage`, `document.cookie`, which may indicate security vulnerabilities (for example, XSS attacks).

**Description of options:**

* `--stdin`: Allows passing code through standard input (for example, with `echo`).
* `--json <path>`: Saves scan results to a file in JSON format.
* `--top <N>`: Option to limit output. Shows only the first N results.
* `--include-node-modules`: Includes the `node_modules` folder in the scan. Use this option if you want to analyze dependencies.
* `--min-entropy <value>`: Sets the entropy threshold for searching high-entropy strings (e.g., tokens and keys).

**Examples:**

Analyze a single file

```
python3 js_sensitive_scan_v0.3.py <path_to_file>
```

Recursive analysis of a folder

```
python3 js_sensitive_scan_v0.3.py <path_to_folder>
```

Using stdin (analyze code passed through the console)

```
echo "const apiKey = 'AIza...';" | python3 js_sensitive_scan_v0.3.py --stdin
```

Save results to JSON

```
python3 js_sensitive_scan_v0.3.py <path_to_file> --json result.json
```

Show only the first N results

```
python3 js_sensitive_scan_v0.3.py <path_to_file> --top <N>
```

Include scanning `node_modules` (not recommended)

```
python3 js_sensitive_scan_v0.3.py <path_to_folder> --include-node-modules
```

Set the entropy threshold for high-entropy string candidates

```
python3 js_sensitive_scan_v0.3.py <path_to_file> --min-entropy <value>
```
