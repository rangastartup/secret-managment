
create:
	python secrets-rotation.py create  secrects-terrraform-admin@secrets-managment.iam.gserviceaccount.com

clean:
	python secrets-rotation.py clean secrects-terrraform-admin@secrets-managment.iam.gserviceaccount.com

get:
	python secrets-rotation.py reterive secrects-terrraform-admin@secrets-managment.iam.gserviceaccount.com

list:
	python secrets-rotation.py list secrects-terrraform-admin@secrets-managment.iam.gserviceaccount.com
	
