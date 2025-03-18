import google.generativeai as genai
from google.api_core.exceptions import ResourceExhausted
import json
import time

def setup_gemini(API):
    try:
        genai.configure(api_key=API)

        model = genai.GenerativeModel(
                    "gemini-1.5-flash-latest",
                    system_instruction="You are a SOC analyst, classifying email body as phishing or safe email. You will detect social engineering tactics to determine email health",
                    generation_config=genai.GenerationConfig(
                        response_mime_type="application/json",
                        temperature = 1.5

                    ),
                )

        return model
    
    except Exception as e:
        print(f"ERROR OCCURED...\n{str(e)}")
        return None
    

def get_analysis_prompt(email):
    starter = f"{email}/n/n classify the following above email as phishing or not and provide answer in the following JSON format\n"
    template = {
        "label" : "Label the email as phishing or safe ONLY",
        "social_tactics": "provide the list of social tactics used for this email if its phishing, if safe return empty list",
        "reasons": "provide your reason of your label using social tactics used if any",
        "phishing_score": "provide a score in 0-1 range of it being phishing"
    }
    
    return (starter + '\n' + str(template))



def body_analyse(model,email, retries=3):
    if email == "": return {}
    prompt = get_analysis_prompt(email)
    attempt = 0
    while attempt < retries:
        try:
            response = model.generate_content(prompt)
            temp_response = response.text
            json_obj = json.loads(response.text)
            return json_obj
        except ResourceExhausted as e:
            attempt += 1
            print(f"ResourceExhausted error encountered. Retrying after 60 seconds, Attempt: {attempt}/{retries}...")
            time.sleep(60)
            print('Resuming')
    
    print("Max retries reached. Could not complete the request.")
    return {}