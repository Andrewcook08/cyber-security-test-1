# CSRF Protections
- CSRF Token ensures that the request comes from the expected website. Prevents Cross-Site Request Forgery.
- Each token is present in any post request to prevent Cross-Site Request Forgery
- Ensures that each request to the server is coming from the expected client
- CSRFProtect handles this
- uses a Flask-WTF token

# Hashed Passwords
- Passwords are now stored as hashes
- If the database ever gets leaked, the hashed passwords provide no meaning.
- use hashing for validation

# Session based cookies
### Sessions use a cryptographically signed cookie that can't be forged:

  session['username'] = 'alice'

  What actually gets stored in the cookie:
  session=eyJ1c2VybmFtZSI6ImFsaWNlIn0.ZxYz1g.HX9YKyfDZVEi_6R5dTlKqS8vN3w
          ↑ Data (encoded)          ↑ Timestamp  ↑ Signature
  
### How Sessions Work

  1. User logs in → Flask creates session data: {'username': 'alice'}
  2. Flask signs this with secret key → Creates tamper-proof cookie
  3. Browser sends cookie back → Flask verifies signature using same secret key
  4. If signature valid → User is authenticated
~~~
 SET SESSION:
  Your Code: session['username'] = 'alice'
       ↓
  Flask: data + SECRET_KEY → Signature
       ↓
  Cookie: {data}.{signature} → Browser

  GET SESSION:
  Browser: {data}.{signature} → Flask
       ↓
  Flask: data + SECRET_KEY → Expected Signature
       ↓
  Compare: signature == expected?
       ↓
  Your Code: Gets 'alice' (or None if tampered)
~~~

### The secret key is never sent to the browser. It's only used server-side to:
  1. Create signatures when setting sessions
  2. Verify signatures when reading sessions

# Purchasing logic now fully lives on the server
- Validate inputs and grab price from the backend rather than from the user.
- Not even able to send a price value to the backend anymore.
- Also added a 100 quantity limit to prevent integer overflow.

# preventing XSS
- escape the new description for the product so that malicious javascript cannot be run in the user's browser.
- Replaces certain characters with safe display codes so that the browser does not view as code that can be run. 

# Admin Protections
- at runtime admin_dashboard is wrapped with the admin_required function that checks if the user is admin when trying to navigate to the admin dashboard. If the user is not admin, then they receive the response and the process ends there, otherwise the admin_dashboard function is called and the user is taken there.
- also added XSS protection by escaping the new product description before setting it. This converts special characters to safe HTML codes so that the browser does not recognize code as code. Preventing malicious code from being run in the users' browser.

# Rate limiting
- Prevent brute force attacks on critical endpoints like purchasing, logging in, creating accounts. 10 requests a minute but we can change it to whatever.
- If a rate limit is hit, our custom 429 handler gets hit.