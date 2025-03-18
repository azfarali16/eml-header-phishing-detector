from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List
import uvicorn
import joblib
from dotenv import load_dotenv
from utils import *
from analyser import *
import os

#setup
app = FastAPI(title="Phishing Email Detection API", description="API to classify emails as phishing or non-phishing", version="0.5.0")
pipe = joblib.load('./model/classifier.pkl')
load_dotenv()
model = setup_gemini(os.getenv("GEMINI_SECRET_KEY"))



#SOME CONSTANTS
desired_headers = [
    'received1', 'received2', 'received3', 'received4', 'received5', 'received6', 
    'received7', 'received8', 'received9', 'received10', 'received11', 'received12', 
    'received13', 'received14', 'received15', 'received16', 'first_received', 'last_received', 
    'hops', 'subject', 'date', 'message-id', 'from', 'return-path', 'to', 'content-type', 
    'mime-version', 'x-mailer', 'content-transfer-encoding', 'x-mimeole', 'x-priority', 
    'list-id', 'lines', 'x-virus-scanned', 'status', 'content-length', 'precedence', 
    'delivered-to', 'list-unsubscribe', 'list-subscribe', 'list-post', 'list-help', 
    'x-msmail-priority', 'x-spam-status', 'sender', 'errors-to', 'x-beenthere', 'list-archive', 
    'reply-to', 'x-mailman-version', 'x-miltered', 'x-uuid', 'x-virus-status', 'x-spam-level', 
    'x-spam-checker-version', 'references', 'in-reply-to', 'user-agent', 'thread-index', 'cc', 
    'received-spf', 'x-original-to', 'content-disposition', 'mailing-list', 'x-spam-check-by', 
    'domainkey-signature', 'importance', 'x-mailing-list',
]

fields = ['from', 'message-id', 'return-path', 'reply-to', 'errors-to', 
          'in-reply-to', 'references', 'to', 'cc', 'sender']


emails_to_check = [('from', 'reply-to')]

domain_fields_to_check = [('message-id_domains', 'from_domains'), ('from_domains', 'return-path_domains'), ('message-id_domains', 'return-path_domains'), ('message-id_domains', 'sender_domains'), ('message-id_domains', 'reply-to_domains'),
                          ('return-path_domains', 'reply-to_domains'), ('reply-to_domains', 'to_domains'), ('to_domains', 'in-reply-to_domains'), ('errors-to_domains', 'message-id_domains'), ('errors-to_domains', 'from_domains'), ('errors-to_domains', 'sender_domains'),
                          ('errors-to_domains', 'reply-to_domains'), ('sender_domains', 'from_domains'), ('references_domains', 'reply-to_domains'), ('references_domains', 'in-reply-to_domains'), ('references_domains', 'to_domains'), ('from_domains', 'reply-to_domains'),
                          ('to_domains', 'from_domains'), ('to_domains', 'message-id_domains')]


def eml2vector(eml_path):
    
    """
    Converts .eml file to a vector feature for the model to predict.
    eml_path - str
        string path for the eml
    Output:
    X - DataFrame
        features
    """
    
    row = extract_headers(eml_path,desired_headers)
    
    df = pd.DataFrame([row])
    df.reset_index(drop=True,inplace=True)
        
    email_dict = {}

    email_dict = {field: extract_emails(df.loc[0,field]) for field in fields}


    email_check_dict = {}
    for val in emails_to_check:
        val1 = val[0]
        val2 = val[1]

        email_check_dict[f"email_match_{val1}_{val2}"] = list_match_check_dict(email_dict[val1],email_dict[val2])

    domain_dict = {field : extract_domains(email_dict[field]) for field in fields}

    #domain check
    domain_check_dict = {}
    for val in domain_fields_to_check:
        val1 = val[0].replace('_domains','')
        val2 = val[1].replace('_domains','')

        domain_check_dict[f"domain_match_{val1}_{val2}"] = list_match_check_dict(domain_dict[val1], domain_dict[val2])

    feature_dict  = {}  
    feature_dict.update(domain_check_dict)
    feature_dict.update(email_check_dict)
    

    return pd.DataFrame([feature_dict])


def predict_phishing(eml_json: dict, pipe):
    """Predict if the input email is phishing or not."""

    X = eml2vector(eml_json)

    y_prob = pipe.predict_proba(X)[0] 
    y = y_prob.argmax() 
    confidence_score = float(y_prob[y].round(2) * 100)  
    label = int(y) 

    prediction = 'phishing' if label == 1 else 'safe'

    return {
        "prediction": prediction,
        'label': label,
        'confidence_score': confidence_score
    }


#header schema
class HeaderRequest(BaseModel):
    header : dict = Field(..., description="The header of email.")

#body schema
class BodyRequest(BaseModel):
    subject : str = Field(..., description="The subject of the email.", example="Urgent! Your account is compromised")
    body: str = Field(..., description="The body content of the email.", example="Dear User, Your account has been flagged. Please click on the link to secure it.")


#response schema
class AnalysedResponse(BaseModel):
    label: str = Field(..., description="Label the email as phishing or safe ONLY", example="phishing")
    social_tactics: List[str] = Field(..., description="Provide the list of social tactics used for this email if it's phishing. If safe, return an empty list.", example=["urgency", "fear"])
    reasons: str = Field(..., description="Provide your reason for the label using social tactics used, if any.", example="This email uses urgency and fear tactics to deceive the user.")
    phishing_score: float = Field(..., description="Provide a score in the 0-1 range of it being phishing", example=0.87)

class PredictionResponse(BaseModel):
    prediction: str = Field(..., description="Prediction label for the email, either 'phishing' or 'safe'", example="phishing")
    label: int = Field(..., description="Label indicating the result of the prediction, 1 for phishing and 0 for safe", example=1)
    confidence_score: float = Field(..., description="The model's confidence score, in the range 0 to 1, representing how confident it is about the prediction", example=0.95)



#predict model
@app.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
async def classify_email(request: HeaderRequest):
    try:
        header = request.header
        if not header:
            raise HTTPException(status_code=400, detail="Header is empty")

        prediction = await predict_phishing(header,pipe)
        print("Prediction",prediction)
        return {
            "status": "success",
            "data": prediction
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


#body anaylyser:
@app.post("/analyze", response_model=AnalysedResponse, tags=["Analyzer"])
async def analyse(request: BodyRequest):
    subject = request.subject
    body = request.body
    email = f"{subject}\n{body}"

    if not email or len(email)<10:
        raise HTTPException(status_code=400, detail="Body is empty of lenght is too short")
    
    print(email)

    response = await body_analyse(model,email,retries=3)

    if response:
        return{
            "status": "success",
            "data": response
        }
    else:
        return{
            "status": "failure",
            "data": {}
        }

    


#live-status
@app.get("/", tags=["Health Check"])
async def root():
    return {"message": "Phishing Email Detection Model API is running!"}


if __name__ == "__main__":
    uvicorn.run(app)
