description: Add an owner check before the object is returned.

Fix pattern for missing object-level access control:
- Keep the existing lookup of the object.
- Keep the authenticated user: the handler already calls an authentication helper and discards its result
  (for example a line like "current_user(request)"). Change that line to store the result
  (for example "user = current_user(request)"). Include that line in your edit range.
- Do not invent attributes or helpers the code does not already use (for example "request.state.user" or
  "request.user"); use only what the handler and the file already have.
- After the object is loaded AND after the existing "not found" check, compare the object's owner with that
  user (for example "if row["owner_id"] != user["id"]:"), using the same way of reading fields that the code
  around it uses.
- If they differ, stop and respond "forbidden" (HTTP 403) using the exception the file already raises.
- Do not change any other behaviour, names, imports or formatting.
