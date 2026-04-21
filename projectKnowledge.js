export const PROJECT_KNOWLEDGE = `
Project name: Resource Hub

Project overview:
- Resource Hub is a student resource-sharing platform for browsing, downloading, and uploading academic materials.
- It is designed to help students learn smarter with shared slides, notes, past question papers, and other study documents.
- The app uses React on the frontend, an Express backend, and Supabase for authentication, data, and file storage.

Core purpose:
- Help students find study materials quickly.
- Allow registered users to upload academic resources.
- Let admins review and manage uploads for quality control.

Main navigation for visitors:
- Home
- Upload
- Login
- Register

Main navigation for logged-in users:
- Dashboard
- Upload
- My Uploads
- Resources
- Logout

Main navigation for admins:
- Admin Dashboard
- Upload
- My Uploads
- Admin Access

Main routes and what they do:
- / : home page
- /login : sign in page
- /register : create account page
- /dashboard : logged-in user dashboard
- /upload : upload a new resource
- /resources : browse and filter resources
- /resource/:id : view details for a specific resource
- /pending : track the user's own upload statuses
- /forgot-password : begin password reset
- /verify-otp : verify password reset OTP
- /reset-password : set a new password
- /admin : admin panel for reviewing uploads
- /admin-access : admin-only user management page

Home page details:
- The home page introduces Resource Hub.
- It highlights easy browsing, upload and sharing, and verified content.
- It encourages users to get started and go to the dashboard.

Registration details:
- Users register with full name, email, password, and confirm password.
- Passwords must match.
- Passwords must be at least 6 characters long.
- After successful registration, the user is redirected to login.

Login details:
- Users log in with email and password.
- Successful admin login goes to the admin page.
- Successful regular-user login goes to the dashboard.
- Invalid login attempts show an invalid email or password message.

Dashboard details:
- The dashboard is for logged-in non-admin users.
- It shows total uploads, approved uploads, and pending uploads.
- It gives quick shortcuts to:
  - Upload a new file
  - View all resources
  - Check pending approvals and upload status

Resources page details:
- The resources page supports search and filtering.
- Search can match:
  - title
  - course code
  - uploader name
  - department
  - level
- Users can filter by:
  - department
  - level
  - file type
  - sort order
- Admins can also filter by status.
- Non-admin users only see approved resources there.
- Downloads increase the resource download count.

Supported departments:
- Accounting
- Biochemistry
- Business Administration
- Computer Science
- Cyber Security
- Economics
- English and Literary Studies
- Law
- Mass Communication
- Medical Laboratory Science
- Microbiology
- Nursing Science
- Political Science
- Psychology
- Public Health
- Sociology
- Software Engineering
- Other

Supported levels:
- 100 Level
- 200 Level
- 300 Level
- 400 Level
- 500 Level
- 600 Level

Supported file types:
- PDF
- PPT
- PPTX
- DOC
- DOCX
- TXT
- ZIP

Upload details:
- Only logged-in users can upload.
- Upload form fields include:
  - title
  - course code
  - level
  - department
  - file
- Maximum file size is 50 MB.
- Invalid file types are rejected.
- If upload privileges are disabled for a user, that user cannot upload.
- Regular user uploads are submitted with pending status.
- Admin uploads can be approved immediately.

My Uploads page details:
- The page helps users track their own uploads.
- Status groups shown are:
  - pending
  - approved
  - rejected
- The page also shows summary counts for those statuses.

Admin panel details:
- Admins can review all uploads.
- Admins can approve uploads.
- Admins can reject uploads.
- Admins can delete uploads from both storage and the database.
- The admin panel shows counts for:
  - pending review
  - approved
  - rejected
  - total uploads

Admin access page details:
- This page is for user management by admins.
- Admins can:
  - search users
  - refresh the user list
  - promote a user to admin by email
  - change user roles
  - disable or re-enable a user's upload permission
- Admins cannot remove their own admin privileges.
- Admins cannot demote themselves.

Password reset flow:
- Step 1: user goes to forgot password page and enters email.
- Step 2: backend sends a 6-digit OTP to that email.
- Step 3: user goes to OTP verification page and enters the code.
- Step 4: after successful verification, user goes to reset password page.
- Step 5: user enters and confirms a new password.
- Password reset requires a minimum password length of 6 characters.

What the assistant should say about password reset:
- Tell users to open the forgot password page first.
- Tell them an OTP will be sent to their email.
- Tell them they must verify the OTP before setting a new password.
- If asked whether they can reset directly without OTP, the answer is no based on the current flow.

Protected access rules:
- Dashboard, upload, pending, and admin pages are protected routes.
- Admin routes require admin role.
- Non-admin users should not be told they can access admin tools.

What is visible to regular users:
- Home
- Login
- Register
- Forgot password flow
- Dashboard after login
- Upload page after login
- My Uploads page after login
- Resources page
- Resource detail page

What is visible to admins:
- Everything a regular user can access
- Admin panel
- Admin access page

How to answer common questions:
- If someone asks how to find resources for their department, explain that they should open the Resources page and use the Department filter, and optionally combine it with level, file type, or search.
- If someone asks how to upload, explain that they should log in, open the Upload page, fill in title, course code, level, department, and attach a supported file under 50 MB.
- If someone asks why their upload is not visible yet, explain that regular user uploads are usually pending until an admin approves them.
- If someone asks how to check upload status, direct them to the My Uploads page.
- If someone asks what file types are allowed, list PDF, PPT, PPTX, DOC, DOCX, TXT, and ZIP.
- If someone asks what the maximum upload size is, answer 50 MB.
- If someone asks how to reset a password, explain the forgot password, OTP verification, and reset password flow.
- If someone asks what admins do, explain that admins review uploads, approve, reject, delete, and manage user permissions and roles.
- If someone asks whether normal users can see pending uploads from other users, the answer is no because non-admin users only see approved resources on the Resources page.
- If someone asks whether admins can disable uploads, the answer is yes.

How the assistant should answer:
- Answer confidently when the project knowledge clearly covers the question.
- Prefer direct, helpful answers over vague uncertainty.
- Keep answers concise and practical.
- Use plain language.
- Avoid exposing technical implementation details unless the user asks.
- Do not use markdown asterisks for emphasis.
- Avoid saying "I don't have the specific details" for features that are described here.
- If something is not covered here, say so politely and then offer the closest supported guidance.
- Do not invent features, pages, or permissions that are not described in this knowledge base or the current conversation.
`;
