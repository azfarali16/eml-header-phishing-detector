import numpy as np
import pandas as pd
import email
from email import policy
from email.parser import BytesParser
import re
import tldextract


#matcher
def list_match_check(row, first_col, second_col):
    list1 = row[first_col]
    list2 = row[second_col]

    if not list1 or not list2:  # Handles empty lists
        return 0

    return int(any(val1 == val2 for val1 in list1 for val2 in list2))


#matcher
def list_match_check_dict(list1,list2):
    # list1 = row[first_col]
    # list2 = row[second_col]

    if not list1 or not list2:  # Handles empty lists
        return 0

    return int(any(val1 == val2 for val1 in list1 for val2 in list2))


#validator
def check_if_valid(dict_to_check, str_val):
    if dict_to_check is None:
        return False
    elif str_val not in dict_to_check:
        return False
    elif dict_to_check[str_val] is None:
        return False
    else:
        return True


# def extract_headers(eml_json,desired_headers):
#     # with open(eml_file, 'rb') as f:
#     #     msg = BytesParser(policy=policy.default).parse(f)
    
#     header_dict = {}
#     for header in desired_headers:
#         header_dict[header] = eml_json.get(header.lower(), '')
    
#     received_headers = eml_json.get_all('received', [])
#     for i, received in enumerate(received_headers[:16]):
#         header_dict[f'received{i+1}'] = received
    
#     if received_headers:
#         header_dict['first_received'] = received_headers[0]
#         header_dict['last_received'] = received_headers[-1]
    
#     header_dict['hops'] = len(received_headers)
    
#     return header_dict


def extract_headers(eml_json,desired_headers):
    msg = {}
    receieved_lst = []
    i = 0
    for x in eml_json['result']['headerLines']:
        header_key = x['key']
        header_value = ':'.join(x['line'].split(':')[1:]).strip()

        if header_key == "received":
            receieved_lst.append(header_value)

        msg[header_key] = header_value

    for r in receieved_lst:
        i+=1
        msg[f'received{i}'] = r

    header_dict = {field : msg.get(field,'') for field in desired_headers}
    if receieved_lst:
        header_dict['first_received'] = receieved_lst[0]
        header_dict['last_received'] = receieved_lst[-1]

    header_dict['hops'] = len(receieved_lst)

    # print(header_dict)

    return header_dict






#FEATURE ENG
# emails in brackets '<>' are matched first, and if none, then other emails are matched
def extract_emails(email_txt):

    if not email_txt or pd.isna(email_txt) or not isinstance(email_txt, str):
        return []
    
    in_brackets = re.findall(r'<([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)>', email_txt)
    if len(in_brackets) == 0:
        not_in_brackets = re.findall(r'([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)',email_txt)
        if len(not_in_brackets) == 0:
            return []
        else:
            return not_in_brackets
    else:
        return in_brackets
    

#extracting domains
# def extract_domains(domain_txt):
#     print('new1')
#     if len(domain_txt) == 0:
#         return []
#     domains_list = []
#     print(domain_txt)
#     for email in domain_txt:
#         if len(email.split('.')) < 2:
#             continue
#         else:
#             main_domain = email.split('@')[-1]
#             # main_domain = main_domain.split('.')[-2:]
#             # main_domain = main_domain[0] + '.' + re.sub('\W+','', main_domain[1])
#             domains_list.append(main_domain.lower())
#     return domains_list


def extract_domains(domain_txt):
    if not domain_txt:
        return []
    
    domains_list = []
    for email in domain_txt:
        if "@" not in email:
            continue
        
        domain = email.split('@')[-1]  # Extract domain from email
        extracted = tldextract.extract(domain)  # Use tldextract to get domain parts

        main_domain = f"{extracted.domain}.{extracted.suffix}"  # Get main domain + suffix
        domains_list.append(main_domain.lower())

    return domains_list
    

# #extracting domains
# def extract_domains(row, col_name):
#     emails_list = row[col_name]
#     if len(emails_list) == 0:
#         return []
    
#     domains_list = []
#     for email in emails_list:
#         if len(email.split('.')) < 2:
#             continue
#         else:
#             main_domain = email.split('@')[-1]
#             main_domain = main_domain.split('.')[-2:]
#             main_domain = main_domain[0] + '.' + re.sub('\W+','', main_domain[1])
#             domains_list.append(main_domain.lower())
    
#     return domains_list


#extract domain from frist received
def get_from_domain_first_received(first_received_val,parser):
    # print(row)
    # first_received_val = row['first_received']
    parsed_val = parser.parse(first_received_val)

    domains_list = []
    if check_if_valid(parsed_val, 'from_hostname'):
        if len(parsed_val['from_hostname'].split('@')) == 2:
            main_domain = parsed_val['from_hostname'].split('@')[-1]
            if len(main_domain.split('.')) >= 2:
                main_domain = main_domain.split('.')[-2:]
                main_domain = main_domain[0] + '.' + re.sub('\W+','', main_domain[1])
                domains_list.append(main_domain.lower())

    if check_if_valid(parsed_val, 'from_name'):
        if len(parsed_val['from_name'].split('@')) == 2:
            main_domain = parsed_val['from_name'].split('@')[-1]
            if len(main_domain.split('.')) >= 2:
                main_domain = main_domain.split('.')[-2:]
                main_domain = main_domain[0] + '.' + re.sub('\W+','', main_domain[1])
                domains_list.append(main_domain.lower())
        
    return domains_list

#extract domains from last recived
def get_for_domain_last_received(last_received_val,parser):
    # last_received_val = row['last_received']
    parsed_val = parser.parse(last_received_val)

    if check_if_valid(parsed_val, 'envelope_for'):
        main_domain = parsed_val['envelope_for'].split('@')[-1]
        main_domain = main_domain.split('.')[-2:]
        main_domain = main_domain[0] + '.' + re.sub('\W+','', main_domain[1])
        return main_domain.lower()
    else:
        return 'NA'
    


def check_for_received_domain_equal(row, field_name,parser):
    field_vals = row[field_name]

    if not isinstance(field_vals, list):
        return 0  # Return 0 if it's NaN or not a list

    for item in field_vals:
        if item == get_for_domain_last_received(row,parser):
            return 1
    return 0


def check_received_from_domain_equal(row, field_name,parser):
    field_vals = row[field_name]

    domains_list_check = get_from_domain_first_received(row,parser)

    for item in field_vals:
        for item2 in domains_list_check:
            if item == item2:
                return 1
    return 0
