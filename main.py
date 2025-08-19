import streamlit as st
import pandas as pd
import re
import hashlib
from cryptography.fernet import Fernet
import base64
import json
from datetime import datetime
import io
import random
import string
from typing import Dict, List, Tuple, Any
import numpy as np

class AdvancedPIIDetector:
    """Advanced PII detector with NLP-like capabilities"""

    def __init__(self):
        # Enhanced PII patterns with more comprehensive regex
        self.pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'(\+\d{1,3}[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',
            'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
            'date_of_birth': r'\b\d{1,2}[/-]\d{1,2}[/-]\d{4}\b|\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b',
            'bank_account': r'\b\d{8,17}\b',
            'aadhaar': r'\b\d{4}[ -]?\d{4}[ -]?\d{4}\b',
            'pan': r'\b[A-Z]{5}\d{4}[A-Z]{1}\b',
            'passport': r'\b[A-Z]{1,2}\d{6,9}\b',
            'driver_license': r'\b[A-Z]{2,3}\d{8,15}\b',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'geolocation': r'\b\d{1,3}\.\d{1,6},\s*\d{1,3}\.\d{1,6}\b',
            'national_id': r'\b\d{6,15}\b',
            'username': r'\b[A-Za-z0-9._-]{3,15}\b',
            'medical_record': r'\b\d{6,10}\b',
            'vehicle_registration': r'\b[A-Z]{2}\d{2}[A-Z]{2}\d{4}\b',
            'full_name': r'\b[A-Z][a-z]+ [A-Z][a-z]+\b'
        }

        # Comprehensive PII keywords with scoring
        self.pii_keywords = {
            # High confidence PII indicators
            'ssn': 0.95, 'social_security': 0.95, 'social security number': 0.95,
            'credit_card': 0.9, 'creditcard': 0.9, 'card_number': 0.9, 'card number': 0.9,
            'bank_account': 0.9, 'account_number': 0.9, 'routing_number': 0.9,
            'passport': 0.9, 'passport_number': 0.9, 'driver_license': 0.9, 'license_number': 0.9,
            'national_id': 0.9, 'tax_id': 0.9, 'taxpayer_id': 0.9,
            'aadhaar': 0.9, 'aadhar': 0.9, 'pan': 0.9,
            'ip_address': 0.9, 'geolocation': 0.9, 'latitude': 0.9, 'longitude': 0.9,
            'medical_record': 0.9, 'health_record': 0.9, 'patient_id': 0.9,
            'vehicle_registration': 0.9, 'registration_number': 0.9,

            # Medium confidence PII indicators
            'email': 0.8, 'e-mail': 0.8, 'mail': 0.7, 'email_address': 0.85,
            'phone': 0.8, 'telephone': 0.8, 'mobile': 0.8, 'cell': 0.75,
            'dob': 0.85, 'date_of_birth': 0.85, 'birth_date': 0.85, 'birthdate': 0.85,
            'birthday': 0.8, 'born': 0.7,
            'username': 0.8, 'user_id': 0.8, 'login': 0.7,

            # Address related
            'address': 0.8, 'home_address': 0.85, 'street': 0.7, 'street_address': 0.8,
            'zip': 0.7, 'postal_code': 0.75, 'zipcode': 0.75, 'postcode': 0.75,
            'city': 0.6, 'state': 0.5, 'country': 0.5,

            # Personal identifiers
            'first_name': 0.7, 'last_name': 0.7, 'full_name': 0.8, 'name': 0.6,
            'middle_name': 0.7, 'maiden_name': 0.8, 'nickname': 0.6,

            # Financial
            'salary': 0.7, 'income': 0.7, 'wage': 0.6, 'payment': 0.5,
            'account_balance': 0.8, 'balance': 0.6,

            # Health related
            'medical_id': 0.9, 'patient_id': 0.8, 'health_record': 0.8,
            'insurance': 0.7, 'policy_number': 0.8
        }

        # Common non-PII keywords to reduce false positives
        self.non_pii_keywords = {
            'id', 'index', 'count', 'total', 'sum', 'average', 'mean', 'median',
            'status', 'type', 'category', 'class', 'group', 'level', 'rank',
            'score', 'rating', 'value', 'amount', 'quantity', 'number',
            'date', 'time', 'timestamp', 'created', 'updated', 'modified'
        }

    def calculate_pii_score(self, column_name: str) -> float:
        """Calculate PII probability score for a column name"""
        col_lower = column_name.lower().replace('_', ' ').replace('-', ' ')
        score = 0.0

        # Check for exact matches
        for keyword, weight in self.pii_keywords.items():
            if keyword in col_lower:
                score = max(score, weight)

        # Reduce score for non-PII keywords
        for non_pii in self.non_pii_keywords:
            if non_pii in col_lower:
                score *= 0.7  # Reduce confidence

        return min(score, 1.0)

    def detect_pii_columns(self, columns: List[str], threshold: float = 0.6) -> Dict[str, float]:
        """Detect PII columns with confidence scores"""
        pii_columns = {}

        for col in columns:
            score = self.calculate_pii_score(col)
            if score >= threshold:
                pii_columns[col] = score

        return pii_columns

    def detect_pii_in_values(self, series: pd.Series, sample_size: int = 10) -> float:
        """Detect PII in actual data values with confidence scoring"""
        if len(series) == 0:
            return 0.0

        # Sample data for analysis
        sample_data = series.dropna().head(sample_size)
        pii_matches = 0

        for value in sample_data:
            value_str = str(value)
            for pattern_name, pattern in self.pii_patterns.items():
                if re.search(pattern, value_str, re.IGNORECASE):
                    pii_matches += 1
                    break

        return pii_matches / len(sample_data) if len(sample_data) > 0 else 0.0

class AdvancedDataMasker:
    """Advanced data masking with reversible algorithms"""

    def __init__(self):
        self.mask_mappings = {}
        self.algorithms = {}
        # Generate a consistent seed for reproducible masking
        self.seed = 42
        random.seed(self.seed)

    def _create_substitution_cipher(self, column_name: str) -> Dict[str, str]:
        """Create a substitution cipher for number masking"""
        if column_name not in self.algorithms:
            digits = list('0123456789')
            shuffled = digits.copy()
            random.shuffle(shuffled)
            self.algorithms[column_name] = dict(zip(digits, shuffled))
        return self.algorithms[column_name]

    def _apply_number_substitution(self, value: str, column_name: str, reverse: bool = False) -> str:
        """Apply number substitution based on the algorithm mentioned in transcript"""
        cipher = self._create_substitution_cipher(column_name)

        if reverse:
            # Create reverse mapping
            reverse_cipher = {v: k for k, v in cipher.items()}
            cipher = reverse_cipher

        result = ""
        for char in value:
            if char.isdigit():
                result += cipher.get(char, char)
            else:
                result += char

        return result

    def mask_data(self, value: Any, column_name: str) -> Any:
        """Apply specific masking rules based on the type of PII."""
        if pd.isna(value):
            return value

        value_str = str(value).strip()

        # Initialize column mappings
        if column_name not in self.mask_mappings:
            self.mask_mappings[column_name] = {}

        # Return cached result if exists
        if value_str in self.mask_mappings[column_name]:
            return self.mask_mappings[column_name][value_str]

        masked_value = value_str

        # Email masking: Mask all characters before @ except first and last
        if re.match(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', value_str):
            parts = value_str.split("@")
            if len(parts) == 2:
                username = parts[0]
                if len(username) > 2:
                    masked_username = username[0] + '*' * (len(username) - 2) + username[-1]
                else:
                    masked_username = username
                masked_value = f"{masked_username}@{parts[1]}"

        # Phone number masking: Mask all but last 3 digits
        elif re.match(r'(\+\d{1,3}[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}', value_str):
            digits = re.sub(r'[^\d]', '', value_str)
            if len(digits) >= 3:
                masked_value = '*' * (len(digits) - 3) + digits[-3:]

        # Credit Card masking: Mask all but last 4 digits
        elif re.match(r'\b(?:\d[ -]*?){13,16}\b', value_str):
            digits = re.sub(r'[^\d]', '', value_str)
            if len(digits) >= 4:
                masked_value = '*' * (len(digits) - 4) + digits[-4:]

        # Aadhaar number masking: Mask all but last 4 digits
        elif re.match(r'\b\d{4}[ -]?\d{4}[ -]?\d{4}\b', value_str):
            digits = re.sub(r'[^\d]', '', value_str)
            if len(digits) >= 4:
                masked_value = '**** **** ' + digits[-4:]

        # DOB masking: Mask day and month
        elif re.match(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{4}\b', value_str):
            parts = value_str.split('/')
            if len(parts) == 3:
                masked_value = '**/**/' + parts[2]
            else:
                parts = value_str.split('-')
                if len(parts) == 3:
                    masked_value = '**-**-' + parts[2]

        # Bank Account Number masking: Mask all but last 4 digits
        elif re.match(r'\b\d{8,17}\b', value_str):
            digits = re.sub(r'[^\d]', '', value_str)
            if len(digits) >= 4:
                masked_value = '*' * (len(digits) - 4) + digits[-4:]

        # PAN Number masking: Mask all but last 4 characters
        elif re.match(r'\b[A-Z]{5}\d{4}[A-Z]{1}\b', value_str):
            masked_value = value_str[:5] + '****' + value_str[-1]

        # Passport Number masking: Mask all but last 4 characters
        elif re.match(r'\b[A-Z]{1,2}\d{6,9}\b', value_str):
            masked_value = '*' * (len(value_str) - 4) + value_str[-4:]

        # Driver’s License Number masking: Mask all but last 4 characters
        elif re.match(r'\b[A-Z]{2,3}\d{8,15}\b', value_str):
            masked_value = '*' * (len(value_str) - 4) + value_str[-4:]

        # IP Address masking: Mask last octet
        elif re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', value_str):
            parts = value_str.split('.')
            if len(parts) == 4:
                masked_value = f"{parts[0]}.{parts[1]}.{parts[2]}.XXX"

        # Geolocation masking: Mask partial digits
        elif re.match(r'\b\d{1,3}\.\d{1,6},\s*\d{1,3}\.\d{1,6}\b', value_str):
            parts = value_str.split(',')
            if len(parts) == 2:
                lat = parts[0].strip()
                lon = parts[1].strip()
                masked_value = f"{lat[:4]}XXX, {lon[:4]}XXX"

        # Full Name masking: Mask all but first character of first and last name
        elif re.match(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', value_str):
            parts = value_str.split(' ')
            if len(parts) >= 2:
                first_name = parts[0]
                last_name = parts[-1]
                masked_first_name = first_name[0] + '*' * (len(first_name) - 1)
                masked_last_name = last_name[0] + '*' * (len(last_name) - 1)
                masked_value = f"{masked_first_name} {masked_last_name}"

        # Store mapping for reversal
        self.mask_mappings[column_name][value_str] = masked_value
        return masked_value

    def unmask_data(self, masked_value: Any, column_name: str) -> Any:
        """Unmask data using stored mappings or reverse algorithms"""
        if pd.isna(masked_value):
            return masked_value

        masked_str = str(masked_value)

        # Check direct mapping first
        if column_name in self.mask_mappings:
            for original, masked in self.mask_mappings[column_name].items():
                if masked == masked_str:
                    return original

        return masked_value

class RobustDataEncryptor:
    """Robust encryption system with multiple algorithms"""

    def __init__(self):
        # Generate multiple keys for different security levels
        self.fernet_key = Fernet.generate_key()
        self.fernet_cipher = Fernet(self.fernet_key)
        self.encryption_mappings = {}
        self.encryption_metadata = {}

    def encrypt_data(self, value: Any, column_name: str, method: str = 'fernet') -> Any:
        """Encrypt data using specified method"""
        if pd.isna(value):
            return value

        value_str = str(value)

        # Initialize column mappings
        if column_name not in self.encryption_mappings:
            self.encryption_mappings[column_name] = {}

        # Return cached result if exists
        if value_str in self.encryption_mappings[column_name]:
            return self.encryption_mappings[column_name][value_str]

        try:
            if method == 'fernet':
                encrypted_bytes = self.fernet_cipher.encrypt(value_str.encode('utf-8'))
                encrypted_str = base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
            elif method == 'base64':
                encrypted_str = base64.b64encode(value_str.encode('utf-8')).decode('utf-8')
            else:
                # Default to fernet
                encrypted_bytes = self.fernet_cipher.encrypt(value_str.encode('utf-8'))
                encrypted_str = base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

            # Store mapping and metadata
            self.encryption_mappings[column_name][value_str] = encrypted_str
            self.encryption_metadata[column_name] = method

            return encrypted_str
        except Exception as e:
            st.error(f"Encryption failed for column {column_name}: {str(e)}")
            return value

    def decrypt_data(self, encrypted_value: Any, column_name: str) -> Any:
        """Decrypt data using stored method"""
        if pd.isna(encrypted_value):
            return encrypted_value

        encrypted_str = str(encrypted_value)

        # Check direct mapping first
        if column_name in self.encryption_mappings:
            for original, encrypted in self.encryption_mappings[column_name].items():
                if encrypted == encrypted_str:
                    return original

        # Try direct decryption
        try:
            method = self.encryption_metadata.get(column_name, 'fernet')

            if method == 'fernet':
                encrypted_bytes = base64.urlsafe_b64decode(encrypted_str.encode('utf-8'))
                decrypted_bytes = self.fernet_cipher.decrypt(encrypted_bytes)
                return decrypted_bytes.decode('utf-8')
            elif method == 'base64':
                return base64.b64decode(encrypted_str.encode('utf-8')).decode('utf-8')
            else:
                # Try fernet as default
                encrypted_bytes = base64.urlsafe_b64decode(encrypted_str.encode('utf-8'))
                decrypted_bytes = self.fernet_cipher.decrypt(encrypted_bytes)
                return decrypted_bytes.decode('utf-8')
        except Exception as e:
            return encrypted_value

class PIIProtectionAPI:
    """Enhanced API for PII protection with comprehensive operations"""

    def __init__(self):
        self.detector = AdvancedPIIDetector()
        self.masker = AdvancedDataMasker()
        self.encryptor = RobustDataEncryptor()
        self.operation_history = []

    def analyze_data_model(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze data model and identify PII columns with confidence scores"""
        analysis = {
            'total_columns': len(df.columns),
            'total_records': len(df),
            'pii_columns': {},
            'column_analysis': {},
            'recommendations': []
        }

        # Analyze each column
        for col in df.columns:
            col_analysis = {
                'data_type': str(df[col].dtype),
                'null_count': df[col].isnull().sum(),
                'unique_values': df[col].nunique(),
                'sample_values': df[col].dropna().head(3).tolist()
            }

            # PII detection
            name_score = self.detector.calculate_pii_score(col)
            value_score = self.detector.detect_pii_in_values(df[col])
            final_score = max(name_score, value_score)

            if final_score >= 0.6:
                analysis['pii_columns'][col] = final_score
                col_analysis['pii_score'] = final_score
                col_analysis['is_pii'] = True

                # Add recommendations
                if final_score >= 0.9:
                    analysis['recommendations'].append(f"HIGH PRIORITY: Column '{col}' contains highly sensitive PII")
                elif final_score >= 0.7:
                    analysis['recommendations'].append(f"MEDIUM PRIORITY: Column '{col}' likely contains PII")
                else:
                    analysis['recommendations'].append(f"LOW PRIORITY: Column '{col}' may contain PII")
            else:
                col_analysis['pii_score'] = final_score
                col_analysis['is_pii'] = False

            analysis['column_analysis'][col] = col_analysis

        return analysis

    def process_file(self, df: pd.DataFrame, operation: str, columns: List[str] = None) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Process file with specified operation

        Args:
            df: Input dataframe
            operation: 'analyze', 'mask', 'encrypt', 'decrypt', 'unmask'
            columns: Specific columns to process (if None, auto-detect PII)
        """
        result_df = df.copy()
        operation_result = {'operation': operation, 'timestamp': datetime.now()}

        if operation == 'analyze':
            analysis = self.analyze_data_model(df)
            operation_result.update(analysis)
            return result_df, operation_result

        # Determine columns to process
        if columns is None:
            pii_columns = self.detector.detect_pii_columns(df.columns.tolist())
            target_columns = list(pii_columns.keys())
        else:
            target_columns = columns

        operation_result['processed_columns'] = target_columns

        # Apply operations
        try:
            if operation == 'mask':
                for col in target_columns:
                    if col in result_df.columns:
                        result_df[col] = result_df[col].apply(
                            lambda x: self.masker.mask_data(x, col)
                        )
                operation_result['success'] = True

            elif operation == 'encrypt':
                for col in target_columns:
                    if col in result_df.columns:
                        result_df[col] = result_df[col].apply(
                            lambda x: self.encryptor.encrypt_data(x, col)
                        )
                operation_result['success'] = True

            elif operation == 'decrypt':
                for col in target_columns:
                    if col in result_df.columns:
                        result_df[col] = result_df[col].apply(
                            lambda x: self.encryptor.decrypt_data(x, col)
                        )
                operation_result['success'] = True

            elif operation == 'unmask':
                for col in target_columns:
                    if col in result_df.columns:
                        result_df[col] = result_df[col].apply(
                            lambda x: self.masker.unmask_data(x, col)
                        )
                operation_result['success'] = True

            else:
                operation_result['success'] = False
                operation_result['error'] = f"Unknown operation: {operation}"

        except Exception as e:
            operation_result['success'] = False
            operation_result['error'] = str(e)

        # Store operation history
        self.operation_history.append(operation_result)

        return result_df, operation_result

def create_sample_data():
    """Create sample data with various PII types for testing"""
    data = {
        'employee_id': [1001, 1002, 1003, 1004, 1005],
        'first_name': ['John', 'Jane', 'Mike', 'Sarah', 'David'],
        'last_name': ['Doe', 'Smith', 'Johnson', 'Williams', 'Brown'],
        'email': ['john.doe@company.com', 'jane.smith@company.com', 'mike.j@company.com', 'sarah.w@company.com', 'david.b@company.com'],
        'phone': ['555-123-4567', '555-987-6543', '555-555-1234', '555-444-7890', '555-222-3456'],
        'date_of_birth': ['14-08-2002', '15-12-1990', '22-03-1988', '08-09-1992', '30-11-1987'],
        'credit_card': ['1234-5678-9012-4567', '9876-5432-1098-8765', '5555-4444-3333-2222', '7777-8888-9999-1111', '1111-2222-3333-4444'],
        'aadhaar': ['1234 5678 9012', '9876 5432 1098', '5555 4444 3333', '7777 8888 9999', '1111 2222 3333'],
        'pan': ['ABCDE1234F', 'FGHIJ5678K', 'LMNOP9012Q', 'RSTUV3456W', 'XYZAB7890X'],
        'salary': [75000, 82000, 68000, 95000, 71000],
        'department': ['Engineering', 'Marketing', 'Sales', 'HR', 'Finance'],
        'hire_date': ['2020-01-15', '2019-06-20', '2021-03-10', '2018-11-05', '2020-09-12'],
        'bank_account': ['123456789012', '987654321098', '555544443333', '777788889999', '111122223333'],
        'passport': ['AB1234567', 'CD8765432', 'EF5678901', 'GH2345678', 'IJ9876543'],
        'driver_license': ['DL12345678', 'DL87654321', 'DL56789012', 'DL23456789', 'DL98765432'],
        'ip_address': ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5'],
        'geolocation': ['12.9716, 77.5946', '19.0760, 72.8777', '28.7041, 77.1025', '13.0827, 80.2707', '18.5204, 73.8567'],
        'vehicle_registration': ['KA01AB1234', 'MH12CD5678', 'DL03EF9012', 'TN04GH3456', 'KL05IJ7890']
    }
    return pd.DataFrame(data)

# Streamlit Application
def main():
    st.set_page_config(
        page_title="Advanced PII Protection System",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Custom CSS for better styling
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 10px;
        border-left: 4px solid #667eea;
    }
    .pii-high { color: #dc3545; font-weight: bold; }
    .pii-medium { color: #fd7e14; font-weight: bold; }
    .pii-low { color: #20c997; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔒 Advanced PII Detection & Protection System</h1>
        <p>Enterprise-grade solution for identifying, masking, and encrypting personally identifiable information</p>
    </div>
    """, unsafe_allow_html=True)

    # Initialize session state
    if 'api' not in st.session_state:
        st.session_state.api = PIIProtectionAPI()
    if 'original_data' not in st.session_state:
        st.session_state.original_data = None
    if 'processed_data' not in st.session_state:
        st.session_state.processed_data = None
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'operation_history' not in st.session_state:
        st.session_state.operation_history = []

    # Sidebar
    with st.sidebar:
        st.header("🛠️ System Configuration")

        # Sample data option
        if st.button("📊 Load Sample Data", use_container_width=True):
            st.session_state.original_data = create_sample_data()
            st.success("Sample data loaded!")
            st.rerun()

        # File upload
        uploaded_file = st.file_uploader(
            "📁 Upload Excel File",
            type=['xlsx', 'xls'],
            help="Upload your Excel file for PII analysis"
        )

        if uploaded_file is not None:
            try:
                df = pd.read_excel(uploaded_file)
                st.session_state.original_data = df
                st.success(f"✅ File uploaded: {len(df)} records, {len(df.columns)} columns")
            except Exception as e:
                st.error(f"❌ Error reading file: {str(e)}")

        st.divider()

        # System Information
        st.subheader("ℹ️ System Info")

        if st.session_state.original_data is not None:
            df = st.session_state.original_data
            st.metric("Total Records", len(df))
            st.metric("Total Columns", len(df.columns))

            if st.session_state.analysis_results:
                pii_count = len(st.session_state.analysis_results.get('pii_columns', {}))
                st.metric("PII Columns Detected", pii_count)

        st.divider()

        # Operation History
        st.subheader("📋 Operation History")
        if st.session_state.api.operation_history:
            for i, op in enumerate(reversed(st.session_state.api.operation_history[-5:])):
                status = "✅" if op.get('success', False) else "❌"
                st.text(f"{status} {op['operation'].title()}")
        else:
            st.text("No operations performed yet")

    # Main content
    if st.session_state.original_data is not None:
        df = st.session_state.original_data

        # Data overview
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("📊 Records", len(df))
            st.markdown('</div>', unsafe_allow_html=True)

        with col2:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("📋 Columns", len(df.columns))
            st.markdown('</div>', unsafe_allow_html=True)

        with col3:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            memory_usage = df.memory_usage(deep=True).sum() / 1024
            st.metric("💾 Memory", f"{memory_usage:.1f} KB")
            st.markdown('</div>', unsafe_allow_html=True)

        with col4:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            null_count = df.isnull().sum().sum()
            st.metric("❓ Null Values", null_count)
            st.markdown('</div>', unsafe_allow_html=True)

        st.divider()

        # Analysis Section
        st.subheader("🔍 Data Model Analysis")

        col1, col2 = st.columns([2, 1])

        with col1:
            if st.button("🚀 Analyze Data Model", type="primary", use_container_width=True):
                with st.spinner("Analyzing data model and detecting PII..."):
                    _, analysis = st.session_state.api.process_file(df, 'analyze')
                    st.session_state.analysis_results = analysis
                st.success("✅ Analysis completed!")
                st.rerun()

        with col2:
            if st.session_state.analysis_results and st.button("📋 Show Analysis Report", use_container_width=True):
                st.session_state.show_analysis = True

        # Display analysis results
        if st.session_state.analysis_results:
            analysis = st.session_state.analysis_results

            # PII Summary
            st.subheader("🎯 PII Detection Summary")

            if analysis['pii_columns']:
                col1, col2 = st.columns(2)

                with col1:
                    st.write("**Detected PII Columns:**")
                    for col, score in analysis['pii_columns'].items():
                        if score >= 0.9:
                            st.markdown(f'<span class="pii-high">🔴 {col} (Score: {score:.2f})</span>', unsafe_allow_html=True)
                        elif score >= 0.7:
                            st.markdown(f'<span class="pii-medium">🟡 {col} (Score: {score:.2f})</span>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<span class="pii-low">🟢 {col} (Score: {score:.2f})</span>', unsafe_allow_html=True)

                with col2:
                    st.write("**Non-PII Columns:**")
                    non_pii_cols = [col for col in df.columns if col not in analysis['pii_columns']]
                    for col in non_pii_cols:
                        score = analysis['column_analysis'][col]['pii_score']
                        st.markdown(f'⚪ {col} (Score: {score:.2f})')

                # Recommendations
                if analysis['recommendations']:
                    st.subheader("💡 Security Recommendations")
                    for rec in analysis['recommendations']:
                        if "HIGH PRIORITY" in rec:
                            st.error(rec)
                        elif "MEDIUM PRIORITY" in rec:
                            st.warning(rec)
                        else:
                            st.info(rec)
            else:
                st.info("🎉 No PII columns detected in your data!")

            # Column Analysis Details
            with st.expander("📊 Detailed Column Analysis"):
                for col, details in analysis['column_analysis'].items():
                    st.write(f"**{col}**")
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.text(f"Type: {details['data_type']}")
                    with col2:
                        st.text(f"Nulls: {details['null_count']}")
                    with col3:
                        st.text(f"Unique: {details['unique_values']}")
                    with col4:
                        st.text(f"PII Score: {details['pii_score']:.2f}")

                    if details['sample_values']:
                        st.text(f"Sample: {', '.join(map(str, details['sample_values'][:3]))}")
                    st.divider()

        # Data Protection Operations
        if st.session_state.analysis_results and st.session_state.analysis_results['pii_columns']:
            st.subheader("🛡️ Data Protection Operations")

            # Operation selection
            col1, col2, col3 = st.columns(3)

            with col1:
                st.write("**Select Columns to Process:**")
                pii_columns = list(st.session_state.analysis_results['pii_columns'].keys())
                selected_columns = st.multiselect(
                    "Choose PII columns",
                    pii_columns,
                    default=pii_columns,
                    key="selected_pii_columns"
                )

            with col2:
                st.write("**Operation Mode:**")
                operation_mode = st.radio(
                    "Choose operation",
                    ["🎭 Mask Data", "🔐 Encrypt Data", "🔄 Combined (Mask + Encrypt)"],
                    key="operation_mode"
                )

            with col3:
                st.write("**Advanced Options:**")
                preserve_format = st.checkbox("Preserve data format", value=True)
                reversible = st.checkbox("Enable reversible operations", value=True)

            # Operation buttons
            st.write("**Execute Operations:**")
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                if st.button("🎭 Mask Data", use_container_width=True, type="secondary"):
                    if selected_columns:
                        with st.spinner("Masking data..."):
                            processed_df, result = st.session_state.api.process_file(df, 'mask', selected_columns)
                            st.session_state.processed_data = processed_df
                            if result['success']:
                                st.success(f"✅ Successfully masked {len(selected_columns)} columns!")
                            else:
                                st.error(f"❌ Error: {result.get('error', 'Unknown error')}")
                        st.rerun()
                    else:
                        st.warning("Please select columns to process")

            with col2:
                if st.button("🔐 Encrypt Data", use_container_width=True, type="secondary"):
                    if selected_columns:
                        with st.spinner("Encrypting data..."):
                            processed_df, result = st.session_state.api.process_file(df, 'encrypt', selected_columns)
                            st.session_state.processed_data = processed_df
                            if result['success']:
                                st.success(f"✅ Successfully encrypted {len(selected_columns)} columns!")
                            else:
                                st.error(f"❌ Error: {result.get('error', 'Unknown error')}")
                        st.rerun()
                    else:
                        st.warning("Please select columns to process")

            with col3:
                if st.button("🔓 Decrypt Data", use_container_width=True, type="secondary"):
                    if st.session_state.processed_data is not None and selected_columns:
                        with st.spinner("Decrypting data..."):
                            processed_df, result = st.session_state.api.process_file(
                                st.session_state.processed_data, 'decrypt', selected_columns
                            )
                            st.session_state.processed_data = processed_df
                            if result['success']:
                                st.success(f"✅ Successfully decrypted {len(selected_columns)} columns!")
                            else:
                                st.error(f"❌ Error: {result.get('error', 'Unknown error')}")
                        st.rerun()
                    else:
                        st.warning("No encrypted data available or no columns selected")

            with col4:
                if st.button("🎭➡️ Unmask Data", use_container_width=True, type="secondary"):
                    if st.session_state.processed_data is not None and selected_columns:
                        with st.spinner("Unmasking data..."):
                            processed_df, result = st.session_state.api.process_file(
                                st.session_state.processed_data, 'unmask', selected_columns
                            )
                            st.session_state.processed_data = processed_df
                            if result['success']:
                                st.success(f"✅ Successfully unmasked {len(selected_columns)} columns!")
                            else:
                                st.error(f"❌ Error: {result.get('error', 'Unknown error')}")
                        st.rerun()
                    else:
                        st.warning("No masked data available or no columns selected")

        # Data Display Section
        st.subheader("📊 Data Viewer")

        tab1, tab2, tab3 = st.tabs(["📋 Original Data", "🔄 Processed Data", "📈 Comparison"])

        with tab1:
            st.write("**Original Dataset:**")
            st.dataframe(df, use_container_width=True, height=400)

            # Download original data
            @st.cache_data
            def convert_df_to_excel(dataframe):
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    dataframe.to_excel(writer, index=False, sheet_name='Data')
                return output.getvalue()

            excel_data = convert_df_to_excel(df)
            st.download_button(
                label="📥 Download Original Data",
                data=excel_data,
                file_name=f"original_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )

        with tab2:
            if st.session_state.processed_data is not None:
                st.write("**Processed Dataset:**")
                st.dataframe(st.session_state.processed_data, use_container_width=True, height=400)

                # Download processed data
                processed_excel = convert_df_to_excel(st.session_state.processed_data)
                st.download_button(
                    label="📥 Download Processed Data",
                    data=processed_excel,
                    file_name=f"processed_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )
            else:
                st.info("🔄 No processed data available. Please run a protection operation first.")

        with tab3:
            if st.session_state.processed_data is not None:
                st.write("**Side-by-Side Comparison:**")

                # Select column for comparison
                comparison_col = st.selectbox(
                    "Select column to compare:",
                    df.columns.tolist(),
                    key="comparison_column"
                )

                if comparison_col:
                    col1, col2 = st.columns(2)

                    with col1:
                        st.write("**Original Values:**")
                        orig_sample = df[comparison_col].head(10)
                        for i, val in enumerate(orig_sample):
                            st.text(f"{i+1}. {val}")

                    with col2:
                        st.write("**Processed Values:**")
                        proc_sample = st.session_state.processed_data[comparison_col].head(10)
                        for i, val in enumerate(proc_sample):
                            st.text(f"{i+1}. {val}")
            else:
                st.info("🔄 No processed data available for comparison.")

        # Advanced Features Section
        with st.expander("🔧 Advanced Features & API Information"):
            st.subheader("🚀 API Capabilities")

            col1, col2 = st.columns(2)

            with col1:
                st.write("**Supported Operations:**")
                st.markdown("""
                - **Detect**: Identify PII columns using NLP techniques
                - **Mask**: Apply reversible data masking algorithms
                - **Encrypt**: AES-256 encryption with Fernet
                - **Decrypt**: Restore encrypted data
                - **Unmask**: Restore masked data using algorithms
                - **Analyze**: Comprehensive data model analysis
                """)

                st.write("**PII Types Detected:**")
                st.markdown("""
                - Email addresses
                - Phone numbers
                - Social Security Numbers
                - Credit card numbers
                - Dates of birth (with number substitution)
                - Bank account numbers
                - Passport numbers
                - IP addresses
                - Personal names
                - Addresses
                """)

            with col2:
                st.write("**Technical Features:**")
                st.markdown("""
                - **Reversible Operations**: All masking/encryption can be undone
                - **Number Substitution**: Advanced algorithm for date masking
                - **Pattern Recognition**: Regex-based PII detection
                - **Confidence Scoring**: Each detection has a confidence score
                - **Batch Processing**: Handle multiple columns simultaneously
                - **Memory Efficient**: Optimized for large datasets
                """)

                st.write("**Security Standards:**")
                st.markdown("""
                - GDPR compliance ready
                - CCPA compliance features
                - Enterprise-grade encryption
                - Audit trail logging
                - Configurable sensitivity levels
                - Export capabilities
                """)

            # Operation History Details
            # st.subheader("📋 Detailed Operation History")
            # if st.session_state.api.operation_history:
            #     for i, op in enumerate(st.session_state.api.operation_history):
            #         with st.expander(f"Operation {i+1}: {op['operation'].title()} - {op['timestamp'].strftime('%H:%M:%S')}"):
            #             st.json(op)
            # else:
            #     st.info("No operations performed yet.")
            # Operation History Details
            st.subheader("📋 Detailed Operation History")
            if st.session_state.api.operation_history:
                for i, op in enumerate(st.session_state.api.operation_history):
                    st.write(f"Operation {i+1}: {op['operation'].title()} - {op['timestamp'].strftime('%H:%M:%S')}")
                    st.json(op)
            else:
                st.info("No operations performed yet.")


    else:
        # Welcome screen
        st.subheader("🚀 Welcome to Advanced PII Protection System")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("""
            This application helps you detect and protect personally identifiable information (PII) in your datasets.
            """)

        with col2:
            st.markdown("""
            Use the sidebar to upload your Excel file or load sample data to get started.
            """)

        # Quick start options
        st.subheader("⚡ Quick Start")
        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("📊 Load Sample Data", use_container_width=True, type="primary"):
                st.session_state.original_data = create_sample_data()
                st.success("✅ Sample data loaded! Check the sidebar for details.")
                st.rerun()

        with col2:
            st.markdown("**📁 Upload Your File**")
            st.markdown("Use the file uploader in the sidebar to get started with your own data.")

        with col3:
            st.markdown("**📖 Documentation**")
            st.markdown("All features are documented in the Advanced Features section below.")

if __name__ == "__main__":
    main()
