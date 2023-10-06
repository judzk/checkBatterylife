# -*- coding: utf-8 -*-
from setuphelpers import *
from bs4 import BeautifulSoup
import json

battery_report_file = makepath('c:','pri','diagnostic_batterie.html')

def get_battery_capacities(html_file=None):

	chars_to_delete = ["â€¯","Â "," mWh"]

	datas = {}

	# Opening the html file
	HTMLFile = open(html_file, "r")
	# Reading the file
	index = HTMLFile.read()
	# Creating a BeautifulSoup object and specifying the parser
	soup = BeautifulSoup(index, "html.parser")

	for div in soup.findAll("table"):
		rows = div.findAll('tr')
		for row in rows:
			if(row.text.find("mWh") > -1):
				if "DESIGN CAPACITY" in (row.text):
					design_capacity =  row.text.split('DESIGN CAPACITY')[-1].rstrip()
					for chars in chars_to_delete:
						design_capacity = design_capacity.replace(chars,"")
					datas["design_capacity"] = design_capacity
				if "FULL CHARGE CAPACITY" in (row.text):
					full_charge_capacity =  row.text.split('FULL CHARGE CAPACITY')[-1].rstrip()
					for chars in chars_to_delete:
						full_charge_capacity = full_charge_capacity.replace(chars,"")
					datas["full_charge_capacity"] = full_charge_capacity

	return(datas)

def get_batteryreport(output_file=None):

	run(f'powercfg /batteryreport /duration 1 /output "{output_file}"')

def install():

	pass

def audit():
	if 'Portable_Battery' in dmi_info():
		get_batteryreport(output_file=battery_report_file)
		battery_capacity = get_battery_capacities(html_file=battery_report_file)
		fullCharge = battery_capacity['full_charge_capacity']
		currentCharge = battery_capacity['design_capacity']
		ratio = "{:.2f}".format((float(fullCharge) / float(currentCharge))*100)
		logging= "Full Charge " +fullCharge + " - "+ "Design Capacity " + currentCharge
		if ratio > '85': # Valeur seuil a définir pour le monitoring
			returnResult = "OK"
		else:
			returnResult = "NOK"

		result = {"returnReason":ratio,"logging":logging,"returnResult": returnResult}
		WAPT.write_audit_data("batteryreport", "result", result)
		print(json.dumps(result)) # On sort l'affichage en json, pour voir la récupérer facilemement dans les requetes psql
		return "OK"
	else:
		return "OK"
