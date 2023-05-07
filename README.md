# ChatGPT Flask Web Application

This project is a Flask web application that provides a user-friendly interface to interact with OpenAI's ChatGPT API. Users can register, log in, and engage in a conversation with the ChatGPT model.

## Features

- User registration and login system
- Secure password storage using bcrypt
- Protected chat route for authenticated users
- Conversational AI powered by OpenAI's ChatGPT API

## Installation

1. Clone the repository

2. Add your OpenAI API key to the root directory in a file called local.env

3. Runn app.py and the website should be live on localhost:5000
The web application should now be running on http://127.0.0.1:5000/


## Usage
Open your browser and navigate to http://127.0.0.1:5000/.
Register for an account or log in using the provided test account (username: testuser, password: testpassword).
Once logged in, you will be redirected to the chat page, where you can start chatting with the ChatGPT model.
Type your message in the input field and press Enter or click the "Send" button to get a response from ChatGPT.
