from flask import Flask, request, render_template, jsonify
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
import pickle
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)

# Load the model
MODEL_PATH = "Random_Forest.pkl"
with open(MODEL_PATH, 'rb') as file:
    model = pickle.load(file)

def prepare_nsl_kdd_data(train_path, test_path, validation_split=0.25, random_state=42):
    # Define column names
    columns = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot',
               'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations',
               'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count',
               'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate',
               'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
               'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate',
               'dst_host_srv_rerror_rate','attack','level']
    
    # Load data
    train_df = pd.read_csv(train_path, sep=",", names=columns)
    test_df = pd.read_csv(test_path, sep=",", names=columns)
    
    # Classify attacks
    Trained_attack = train_df.attack.map(lambda a: 0 if a == 'normal' else 1)
    Tested_attack = test_df.attack.map(lambda a: 0 if a == 'normal' else 1)

    train_df['attack_state'] = Trained_attack
    test_df['attack_state'] = Tested_attack
    
    # One-hot encoding
    train_df = pd.get_dummies(train_df,columns=['protocol_type','service','flag'], prefix="", prefix_sep="")
    test_df = pd.get_dummies(test_df,columns=['protocol_type','service','flag'],prefix="",prefix_sep="")
    
    LE = LabelEncoder()
    attack_LE= LabelEncoder()
    train_df['attack'] = attack_LE.fit_transform(train_df["attack"])
    test_df['attack'] = attack_LE.fit_transform(test_df["attack"])
    
    # Data Splitting
    X_train = train_df.drop(['attack', 'level', 'attack_state'], axis=1)
    X_test = test_df.drop(['attack', 'level', 'attack_state'], axis=1)

    Y_train = train_df['attack_state']
    Y_test = test_df['attack_state']
    
    X_train_train, X_test_train, Y_train_train, Y_test_train = train_test_split(X_train, Y_train, test_size= 0.25 , random_state=42)
    X_train_test, X_test_test, Y_train_test, Y_test_test = train_test_split(X_test, Y_test, test_size= 0.25 , random_state=42)
    
    # Data scaling
    Ro_scaler = RobustScaler()
    X_train_train = Ro_scaler.fit_transform(X_train_train) 
    X_test_train= Ro_scaler.transform(X_test_train)
    X_train_test = Ro_scaler.fit_transform(X_train_test) 
    X_test_test= Ro_scaler.transform(X_test_test)
    
    X_train = X_train.astype(int)
    X_test = X_test.astype(int)
    
    return (X_train_train, Y_train_train, X_test_train, Y_test_train, X_test, Y_test)


def load_model_and_predict(model_path, X_train, Y_train, X_test, Y_test):
    # Load the model
    with open(model_path, 'rb') as file:
        loaded_model = pickle.load(file)
    
    # Make predictions
    train_predictions = loaded_model.predict(X_train)
    test_predictions = loaded_model.predict(X_test)
    
    # Calculate scores
    train_score = accuracy_score(Y_train, train_predictions)
    test_score = accuracy_score(Y_test, test_predictions)
    
    # Map numeric predictions to labels
    label_map = {0: 'normal', 1: 'attack'}
    train_predictions_labels = np.array([label_map[pred] for pred in train_predictions])
    test_predictions_labels = np.array([label_map[pred] for pred in test_predictions])
    
    return train_score, test_score, train_predictions_labels, test_predictions_labels

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'})
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'})
        if file and file.filename.lower().endswith(('.csv', '.txt')):
            # Save the uploaded file temporarily
            upload_path = "uploaded_test.txt"
            file.save(upload_path)
            
            # Preview the data
            columns = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot',
                       'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations',
                       'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count',
                       'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate',
                       'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
                       'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate',
                       'dst_host_srv_rerror_rate']  # Removed 'attack' and 'level'
            df = pd.read_csv(upload_path, names=columns + ['attack', 'level'])
            preview = df[columns].head(10).to_html(classes='table table-striped table-bordered', table_id="previewTable")
            
            return jsonify({'preview': preview, 'columns': columns})
        else:
            return jsonify({'error': 'Invalid file type. Please upload a .csv or .txt file.'})
    return render_template('upload.html')

@app.route('/predict', methods=['POST'])
def predict():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    if file and file.filename.lower().endswith(('.csv', '.txt')):
        # Save the uploaded file temporarily
        upload_path = "uploaded_test.txt"
        file.save(upload_path)
        
        # Prepare data
        X_train_train, Y_train_train, X_test_train, Y_test_train, X_test, Y_test = prepare_nsl_kdd_data("nsl-kdd-data/KDDTrain+.txt", upload_path)
        
        # Make predictions
        train_score, test_score, train_pred_labels, test_pred_labels = load_model_and_predict(
            MODEL_PATH, 
            X_train_train, 
            Y_train_train, 
            X_test_train, 
            Y_test_train   
        )
        
        # Prepare results
        predictions = test_pred_labels[:10].tolist()  # Get first 10 predictions
        
        return jsonify({
            'predictions': predictions,
            'train_score': f"Training Score: {train_score:.4f}",
            'test_score': f"Testing Score: {test_score:.4f}"  # This is actually the validation score
        })
    return jsonify({'error': 'Invalid file type. Please upload a .csv or .txt file.'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)