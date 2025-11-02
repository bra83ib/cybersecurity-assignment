# Manual Cybersecurity Testing Guide - FinTech App

## Prerequisites
1. Start the Flask application: `python app.py`
2. Navigate to `http://localhost:5000`
3. Create multiple test user accounts for testing transfers

## Test Cases

| No. | Test Case | Action Performed | Expected Outcome | How to Test |
|-----|-----------|------------------|------------------|-------------|
| 1 | SQL Injection - Login | Enter `'OR 1=1--` in email field | Input rejected/error handled | Try logging in with SQL injection payload |
| 2 | Password Strength | Try weak password `12345` | Registration rejected with warning | Register with weak password |
| 3 | XSS Prevention | Add `<script>alert('xss')</script>` in username | Input sanitized/escaped | Try registering with script tags |
| 4 | Unauthorized Access | Access `/dashboard` without login | Redirected to login page | Open dashboard URL in incognito mode |
| 5 | Session Expiry | Wait 5+ minutes after login | Auto logout occurs | Login and wait 5+ minutes, then try to access dashboard |
| 6 | Logout Functionality | Click logout button | Session destroyed, redirected to home | Login, then click logout |
| 7 | Data Confidentiality | Check `fintech.db` file | Passwords are hashed (not plaintext) | Open database file with SQLite browser |
| 8 | File Upload Validation | Try uploading `.exe` file | File rejected with error message | Use upload feature with executable file |
| 9 | Error Message Leakage | Entered invalid query | Generic error shown, no stack trace | Try accessing non-existent transaction ID |
| 10 | Input Length Validation | Enter 5000+ characters in text field | Validation triggered, input rejected | Try very long strings in forms |
| 11 | Duplicate User Registration | Register with existing email | Error displayed, registration blocked | Try registering same email twice |
| 12 | Number Field Validation | Enter letters in amount field | Input rejected with validation error | Enter "abc" in transfer amount |
| 13 | Password Match Check | Enter mismatched confirm password | Registration blocked with error | Register with different confirm password |
| 14 | Data Modification Attempt | Try accessing other user's transactions | Access denied | Manually change user ID in URL/form |
| 15 | Email Validation | Enter invalid email `abc@` | Validation error shown | Try registering with malformed email |
| 16 | Login Attempt Lockout | 5+ failed login attempts | Account locked temporarily | Try wrong password 5+ times |
| 17 | Secure Error Handling | Force divide-by-zero error | App doesn't crash, controlled message | Visit `/test_error?type=divide_zero` |
| 18 | Encrypted Record Check | View transaction details in DB | Sensitive data encrypted | Check encrypted_details field in DB |
| 19 | Input Encoding | Use Unicode emoji in input fields | App handles gracefully | Enter emoji characters in forms |
| 20 | Empty Field Submission | Leave fields blank and submit | Validation warnings displayed | Submit empty forms |
| 21 | Transfer Email Validation | Use invalid email in transfer | Transfer rejected | Try transferring to invalid email |
| 22 | Audit Logs Access | View personal audit logs | Only user's logs visible | Check audit logs page |
| 23 | System Logs Filtering | Filter system logs by action | Filtered results shown | Use filter dropdown in system logs |
| 24 | CSV Download | Download audit logs | CSV file generated | Click download button in audit logs |
| 25 | Transfer to Self | Try transferring to own email | Transfer blocked with error | Enter your own email in transfer form |

## Enhanced Testing Instructions

### Transfer Functionality Test
```
1. Register two users: user1@test.com and user2@test.com
2. Login as user1@test.com
3. Go to Transfer page
4. Enter user2@test.com as recipient
5. Enter amount (e.g., $50)
6. Submit transfer
7. Verify: Transfer successful, balances updated
8. Check audit logs for transfer record
```

### Audit Logs Test
```
1. Login to application
2. Perform various actions (deposit, withdraw, transfer)
3. Go to "My Activity Logs" from user menu
4. Verify: All actions are logged with timestamps
5. Click "Download CSV" to test export functionality
6. Verify: CSV file contains all log entries
```

### System Logs Test
```
1. Login to application
2. Go to "System Logs" from user menu
3. Use filter dropdown to filter by specific actions
4. Verify: Logs are filtered correctly
5. Test pagination if many logs exist
6. Verify: All system activities are captured
```

## Security Features Added

1. **Email-based Transfers**: More secure than username-based transfers
2. **Comprehensive Audit Logging**: All user actions tracked
3. **Log Viewing Interface**: Users can view their activity
4. **System Log Monitoring**: Admin-level log viewing
5. **CSV Export**: Download audit trails for compliance
6. **Advanced Filtering**: Filter logs by action type
7. **Enhanced Transfer UI**: Better user experience with real-time balance calculation

## Expected Security Behaviors

1. **Input Validation**: All user inputs should be validated and sanitized
2. **Authentication**: Strong password requirements enforced
3. **Authorization**: Users can only access their own data
4. **Session Management**: Automatic timeout and secure logout
5. **Error Handling**: Generic error messages, no sensitive information exposed
6. **Audit Logging**: All important actions logged
7. **File Security**: Only safe file types allowed
8. **Data Protection**: Sensitive data encrypted in database

## Test Results Template

| Test No. | Pass/Fail | Notes |
|----------|-----------|-------|
| 1 | | |
| 2 | | |
| ... | | |

Record your test results and any security issues found.
