description: Use a parameterized query instead of building the SQL text from input.

Fix pattern for SQL built from request input:
- Replace the string concatenation or formatting with a query that contains placeholders (for example "?" for sqlite3).
- Pass the values as a separate parameters argument to the execute call, never inside the SQL text.
- If the value is used with LIKE, put the wildcard characters in the parameter value, not in the SQL text.
- Keep the query's meaning, column names and result handling the same.
- Do not change any other behaviour, names, imports or formatting.
