# app.py
from flask import Flask, redirect, request, session, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import os

def get_gmail_service():
    creds_dict = session.get('credentials')
    if not creds_dict:
        return None
    credentials = Credentials(**creds_dict)
    return build('gmail', 'v1', credentials=credentials)


def categorize_email(email):
    # Combine subject and snippet for analysis
    text = (email['subject'] + " " + email['snippet']).lower()
    
    # Define keywords for each category
    if any(keyword in text for keyword in ['meeting', 'project', 'deadline', 'work', 'team']):
        return 'Work'
    elif any(keyword in text for keyword in ['intern', 'internship', 'training', 'program']):
        return 'Internship'
    elif any(keyword in text for keyword in ['assignment', 'exam', 'course', 'study', 'class']):
        return 'Study'
    else:
        return 'Other'
    
    

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a random, secure string

# Path to the client secrets file you downloaded
CLIENT_SECRETS_FILE = "client_secrets.json"

# Set up OAuth 2.0 flow
flow = Flow.from_client_secrets_file(
    CLIENT_SECRETS_FILE,
    scopes=['https://www.googleapis.com/auth/gmail.readonly'],  # Read-only access to emails
    redirect_uri='http://localhost:5000/callback'
)

@app.route('/')
def index():
    if 'credentials' not in session:
        return render_template('login.html')
    
    service = get_gmail_service()
    if not service:
        return "Something went wrong. <a href='/login'>Try again</a>"
    
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=40).execute()
    messages = results.get('messages', [])
    
    if not messages:
        return "No emails found in your inbox."
    
    email_list = []
    for msg in messages:
        email = service.users().messages().get(userId='me', id=msg['id']).execute()
        subject = next(
            header['value'] for header in email['payload']['headers'] if header['name'] == 'Subject'
        )
        category = categorize_email({'subject': subject, 'snippet': email['snippet']})
        email_list.append({'subject': subject, 'snippet': email['snippet'], 'category': category})
    # Temporary display of raw data
    return render_template('index.html', emails=email_list)

@app.route('/login')
def login():
    # Generate the authorization URL and redirect the user to Google
    authorization_url, state = flow.authorization_url(
        access_type='offline',  # Allows refresh tokens
        include_granted_scopes='true'
    )
    session['state'] = state  # Store state to verify later
    return redirect(authorization_url)

@app.route('/disconnect')
def disconnect():
    session.pop('credentials', None)
    return "Disconnected from Gmail. <a href='/'>Go back</a>"

@app.route('/callback')
def callback():
    # Handle the callback from Google after user grants permission
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    # Store credentials in the session
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect('/')

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 
    app.run(port=5000, debug=True)