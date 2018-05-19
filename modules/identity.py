#!/usr/bin/python
"""fake identity module."""

import random

from faker import Faker

from termcolor import colored


def race_selection():
    """Choose race."""
    fake = Faker()
    print colored('Name: ' + fake.name(), 'green')
    race_picker = random.randint(0, 5)

    race = {
        0: 'Caucasian',
        1: 'African-American',
        2: 'Mexican',
        3: 'Indian',
        4: 'Asian',
        5: 'Native American'
    }

    race_type = race.get(race_picker)
    print colored('Race: ' + race_type, 'green')


def height_selection():
    """Choose height."""
    feet = 5
    inches = random.randint(1, 11)
    height = str(feet) + "'" + str(inches) + '"'
    print colored('Height: ' + height, 'green')


def weight_selection():
    """Choose weight."""
    pounds = random.randint(120, 300)
    sub_pounds = random.randint(0, 9)
    weight = str(pounds) + '.' + str(sub_pounds)
    print colored('Weight: ' + weight, 'green')


def blood_selection():
    """Choose blood type."""
    blood_picker = random.randint(0, 7)

    blood = {
        0: 'A+',
        1: 'A-',
        2: 'B+',
        3: 'B-',
        4: 'AB+',
        5: 'AB-',
        6: 'O+',
        7: 'O-'
    }

    blood_type = blood.get(blood_picker)
    print colored('Blood type: ' + blood_type, 'green')


def ssn_selection():
    """Choose SSN."""
    first_ssn = random.randint(100, 999)
    second_snn = random.randint(10, 99)
    third_ssn = random.randint(1000, 9999)
    social = (str(first_ssn) + '-' +
              str(second_snn) + '-' +
              str(third_ssn))

    print colored('SSN: ' + social, 'green')


def number_selection():
    """Choose number."""
    first_num = random.randint(100, 999)
    second_num = random.randint(100, 999)
    third_num = random.randint(1000, 9999)
    phone_number = ('(' + str(first_num) + ')' +
                    str(second_num) + '-' +
                    str(third_num))

    print colored('Phone number: ' + phone_number, 'green')


def month_selection():
    """Choose DOB."""
    month_picker = random.randint(0, 11)
    yold = random.randint(18, 80)
    year = 2018 - yold
    day = random.randint(1, 28)

    month = {
        0: 'Jan',
        1: 'Feb',
        2: 'Mar',
        3: 'Apr',
        4: 'May',
        5: 'Jun',
        6: 'Jul',
        7: 'Aug',
        8: 'Sep',
        9: 'Oct',
        10: 'Nov',
        11: 'Dec'
    }

    exact_month = month.get(month_picker)
    date = exact_month + ' ' + str(day) + ' ' + str(year)
    print colored('DOB: ' + date, 'green')


def address_selection():
    """Choose address."""
    fake = Faker()
    address = fake.address()
    print colored('Address: ' + address, 'green')


def job_selection():
    """Choose job."""
    job_picker = random.randint(0, 19)

    jobs = {
        0: 'Teacher Assistant',
        1: 'Urban Planner',
        2: 'Painter',
        3: 'Zoologist',
        4: 'Musician',
        5: 'Interpreter & Translator',
        6: 'Marketing Manager',
        7: 'Loan Officer',
        8: 'Microbiologist',
        9: 'Customer Service Representative',
        10: 'Computer Programmer',
        11: 'High School Teacher',
        12: 'Substance Abuse Counselor',
        13: 'Mechanical Engineer',
        14: 'Drafter',
        15: 'Preschool Teacher',
        16: 'Environmental scientist',
        17: 'Automotive mechanic',
        18: 'Insurance Agent',
        19: 'Veterinarian'
    }

    job = jobs.get(job_picker)
    print colored('Occupation: ' + job, 'green')


def email_selection():
    """Choose email."""
    email_picker = random.randint(0, 19)

    email = {
        0: 'leviathan@comcast.net',
        1: 'sportsfan@comcast.net',
        2: 'heroine@yahoo.ca',
        3: 'jigsaw@gmail.com',
        4: 'moonlapse@optonline.net',
        5: 'ninenine@outlook.com',
        6: 'warrior@aol.com',
        7: 'crimsane@yahoo.ca',
        8: 'world@comcast.net',
        9: 'singer@verizon.net',
        10: 'sumdumass@att.net',
        11: 'payned@yahoo.com',
        12: 'shrapnull@comcast.net',
        13: 'curly@optonline.net',
        14: 'mschilli@comcast.net',
        15: 'empathy@sbcglobal.net',
        16: 'codex@optonline.net',
        17: 'ehood@yahoo.com',
        18: 'nacho@outlook.com',
        19: 'crusader@icloud.com'
    }

    exact_email = email.get(email_picker)
    print colored('Email: ' + exact_email, 'green')


def credit_selection():
    """Choose SSN."""
    type_picker = random.randint(0, 3)
    first_num = random.randint(1000, 9999)
    second_num = random.randint(1000, 9999)
    third_num = random.randint(1000, 9999)
    forth_num = random.randint(1000, 9999)
    cvv_picker = random.randint(100, 999)
    credit_number = (str(first_num) + ' ' +
                     str(second_num) + ' ' +
                     str(third_num) + ' ' +
                     str(forth_num))

    credit_type = {
        0: 'Visa',
        1: 'MasterCard',
        2: 'Discover',
        3: 'American Express'
    }

    first_date = random.randint(1, 12)
    second_date = random.randint(18, 22)
    credit_date = (str(first_date) + '/' +
                   str(second_date))

    get_type = credit_type.get(type_picker)
    print colored('Credit card: ', 'green')
    print colored(get_type, 'green')
    print colored(credit_number, 'green')
    print colored(cvv_picker, 'green')
    print colored(credit_date, 'green')


def color_selection():
    """Choose favorite color."""
    color_picker = random.randint(0, 9)

    color = {
        0: 'blue',
        1: 'green',
        2: 'red',
        3: 'orange',
        4: 'yellow',
        5: 'purple',
        6: 'pink',
        7: 'black',
        8: 'white',
        9: 'gray'
    }

    fav_color = color.get(color_picker)
    print colored('Favorite color: ' + fav_color, 'green')


def fake_identity():
    """Generate a fake identity."""
    race_selection()
    height_selection()
    weight_selection()
    blood_selection()
    ssn_selection()
    number_selection()
    address_selection()
    job_selection()
    email_selection()
    credit_selection()
    color_selection()
