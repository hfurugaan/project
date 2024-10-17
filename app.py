import os
from flask import Flask, request, render_template, jsonify
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
import pickle
from sklearn.metrics import accuracy_score

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
    train_df['attack_state'] = train_df.attack.map(lambda a: 0 if a == 'normal' else 1)
    test_df['attack_state'] = test_df.attack.map(lambda a: 0 if a == 'normal' else 1)
    
    # One-hot encoding
    categorical_columns = ['protocol_type', 'service', 'flag']
    train_df_encoded = pd.get_dummies(train_df, columns=categorical_columns, prefix=categorical_columns, prefix_sep="_")
    test_df_encoded = pd.get_dummies(test_df, columns=categorical_columns, prefix=categorical_columns, prefix_sep="_")
    
    # Ensure both train and test have the same columns
    all_columns = set(train_df_encoded.columns) | set(test_df_encoded.columns)
    for col in all_columns:
        if col not in train_df_encoded.columns:
            train_df_encoded[col] = 0
        if col not in test_df_encoded.columns:
            test_df_encoded[col] = 0
    
    # Ensure columns are in the same order
    train_df_encoded = train_df_encoded.reindex(sorted(train_df_encoded.columns), axis=1)
    test_df_encoded = test_df_encoded.reindex(sorted(train_df_encoded.columns), axis=1)
    
    # Prepare features and target
    drop_columns = ['attack', 'level', 'attack_state']
    X_train = train_df_encoded.drop(drop_columns, axis=1)
    Y_train = train_df_encoded['attack_state']
    X_test = test_df_encoded.drop(drop_columns, axis=1)
    Y_test = test_df_encoded['attack_state']
    
    # Add zero columns for missing features
    current_feature_count = X_train.shape[1]
    missing_feature_count = 124 - current_feature_count
    
    if missing_feature_count > 0:
        for i in range(missing_feature_count):
            column_name = f'added_feature_{i}'
            X_train[column_name] = 0
            X_test[column_name] = 0
    
    # Ensure we have 124 features
    assert X_train.shape[1] == 124, f"Expected 124 features, but got {X_train.shape[1]}"
    assert X_test.shape[1] == 124, f"Expected 124 features, but got {X_test.shape[1]}"
    
    # Split training data into train and validation sets
    X_train_train, X_test_train, Y_train_train, Y_test_train = train_test_split(X_train, Y_train, 
                                                                                test_size=validation_split, 
                                                                                random_state=random_state)
    
    # Scale the features
    scaler = RobustScaler()
    X_train_train_scaled = scaler.fit_transform(X_train_train)
    X_test_train_scaled = scaler.transform(X_test_train)
    X_test_scaled = scaler.transform(X_test)
    
    return (X_train_train_scaled, Y_train_train, X_test_train_scaled, Y_test_train, X_test_scaled, Y_test)

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
        train_score, test_score, train_pred_labels, test_pred_labels = load_model_and_predict(MODEL_PATH, X_train_train, Y_train_train, X_test, Y_test)
        
        # Prepare results
        predictions = test_pred_labels[:10].tolist()  # Get first 10 predictions
        
        return jsonify({
            'predictions': predictions,
            'train_score': f"Training Score: {train_score:.4f}",
            'test_score': f"Testing Score: {test_score:.4f}"
        })
    return jsonify({'error': 'Invalid file type. Please upload a .csv or .txt file.'})

if __name__ == '__main__':
    app.run(debug=True)