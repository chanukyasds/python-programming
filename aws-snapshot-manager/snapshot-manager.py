import boto3 
import yaml 
import argparse
from tabulate import tabulate 
import warnings
from datetime import datetime

warnings.filterwarnings('ignore')
rds_client = boto3.client('rds' ,verify=False)

# define global variables
global_data = {}

#functions
def read_yaml():
    with open('default_config.yaml', 'r') as file:
        defaults = yaml.safe_load(file)
    with open('custom_config.yaml', 'r') as file:
        config = yaml.safe_load(file)
    return defaults, config


def is_config_empty(global_data):
    empty_config = []
    for key, value in global_data.items():
        if value is None or value == "":
            empty_config.append(key)
    if empty_config:
        print("\nPlease update yaml configuration:")
        return True
    return False

def db_source(db_name):
    defaults, config = read_yaml()
    if db_name == 'prod':
        global_data['db_instance_identifier'] = config['rds_prod_db_instance_identifier']
    elif db_name == 'test':
        global_data['db_instance_identifier'] = config['rds_test_db_instance_identifier']
    elif db_name == 'dev':
        global_data['db_instance_identifier'] = config['rds_dev_db_instance_identifier']
    else:
        print("\n Database source can be prod, test or dev")
        exit()
    if db_name in ['prod','test','dev']:
        global_data['snapshot_identifier'] = global_data['db_instance_identifier']+"-snapshot"+datetime.now().strftime("-%Y%m%d-%H%M%S")
        # for snapshot copy
        global_data['copy_suffix']= defaults['default_snapshot_copy_identifier_suffix']
        global_data['copy_region']= defaults['default_copy_region']
        global_data['kms_key']= defaults['default_snapshot_kms_key_arn']
        # for snapshot share
        global_data['target_aws_account']= defaults['default_test_account_id']
    
    if not is_config_empty(global_data):
        return global_data
    else:
        exit(0)
    


def is_snapshot_exists(snapshot_id):
    try:
        response = rds_client.describe_db_snapshots(
        DBSnapshotIdentifier=snapshot_id
        )
        if len(response['DBSnapshots']) > 0:
            return True
    except Exception as e:
        return False

def is_dbinstance_exists(db_identifier):
    try:
        response = rds_client.describe_db_instances(
        )
        DBInstanceIdentifier=db_identifier
        return True
    except Exception as e:
        print("\nNo DB Instance exists with name {0}".format(db_identifier))
        return False

# used to check while creating copy snapshot
def is_snapshot_available(snapshot_id):
    if is_snapshot_exists(snapshot_id):
        try:
            response = rds_client.describe_db_snapshots(
                DBSnapshotIdentifier=snapshot_id
            )
            snapshot = response['DBSnapshots']
            if snapshot[0]['Status'] == 'available':
                return True
            else:
                print("\nSnapshot {0} is not in available state".format(snapshot_id))
                return False
        except Exception as e:
            print("Error:", e)
    else:
        print("\nNo snapshot exists with name {0}".format(snapshot_id))

def is_db_creating_snapshot_currently(db_identifier):
    db_instance_identifier = db_identifier
    if is_dbinstance_exists(db_instance_identifier):
        try:
            response = rds_client.describe_db_snapshots(
                DBInstanceIdentifier=db_instance_identifier,
                SnapshotType='manual'
            )
            snapshots = response['DBSnapshots']
            if snapshots:
                for snapshot in snapshots:
                    if snapshot['Status'] == 'creating':
                        print("\nDB Instance not available because its currently creating snapshot called {0}".format(snapshot['DBSnapshotIdentifier']))
                        return True
                return False
            else:
                return False
        except Exception as e:
            print("Error:", e)

def create_snapshot(snapshot_id=None):
    if snapshot_id is None:
        db_instance_identifier = global_data['db_instance_identifier']
        snapshot_identifier = global_data['snapshot_identifier']
    else:
        db_instance_identifier = global_data['db_instance_identifier']
        snapshot_identifier = snapshot_id
    if is_dbinstance_exists(db_instance_identifier) and not is_snapshot_exists(snapshot_identifier) and not is_db_creating_snapshot_currently(db_instance_identifier):
        try:
            response = rds_client.create_db_snapshot(
                DBSnapshotIdentifier=snapshot_identifier,
                DBInstanceIdentifier=db_instance_identifier
            )
            print("\nSnapshot {0} created successfully!".format(snapshot_identifier))
        except Exception as e:
            print("\nError creating snapshot:{0}".format(snapshot_identifier), e)
    else:
        if is_snapshot_exists(snapshot_identifier):
            print("\nA snapshot with name {0} already exist.".format(snapshot_identifier))

def delete_snapshot(snapshot_id):
    snapshot_identifier = snapshot_id
    if is_snapshot_exists(snapshot_identifier):
        try:
            response = rds_client.delete_db_snapshot(
                DBSnapshotIdentifier=snapshot_identifier
            )
            print("Snapshot deleted successfully!")
        except Exception as e:
            print("Error deleting snapshot:", e)
    else:
        print("\nNo snapshot found with name {0}".format(snapshot_identifier))

def copy_snapshot(snapshot_id):
    source_snapshot_identifier = snapshot_id
    target_snapshot_identifier = source_snapshot_identifier + global_data['copy_suffix']
    if is_snapshot_exists(source_snapshot_identifier) and not is_snapshot_exists(target_snapshot_identifier) and is_snapshot_available(source_snapshot_identifier):
        try:
            response = rds_client.copy_db_snapshot(
                SourceDBSnapshotIdentifier=source_snapshot_identifier,
                TargetDBSnapshotIdentifier=target_snapshot_identifier,
                KmsKeyId=global_data['kms_key']
            )
            print("\nSnapshot copied successfully")
        except Exception as e:
            print("\nError:", e)
    else:
        if not is_snapshot_exists(source_snapshot_identifier):
            print("\nSource snapshot {0} doesn't found.".format(source_snapshot_identifier))
        if is_snapshot_exists(target_snapshot_identifier):
            print("\nTarget snapshot {0} already exist.".format(target_snapshot_identifier))
        print("\nUse option --snapshot-list to list all snapshots")

def share_snapshot(snapshot_id):
    snapshot_identifier = snapshot_id
    target_aws_account = global_data['target_aws_account']
    # we don't need to check explicitly about to check if a snapshot is already shared aws won't throw error even we share to same account
    if is_snapshot_exists(snapshot_identifier) and is_snapshot_available(snapshot_identifier):
        try:
            response = rds_client.modify_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot_identifier,
                AttributeName='restore',
                ValuesToAdd=[target_aws_account]
            )
            print("\nSnapshot shared successfully")
        except Exception as e:
            print("\nError:", e)
    else:
        if not is_snapshot_exists(snapshot_identifier):
            print("\nNo snapshot found with name {0}.".format(snapshot_identifier))
        print("\nUse option --snapshot-list to list all snapshots")

def retain_snapshot(snapshot_id):
    snapshot_identifier = snapshot_id
    target_aws_account = global_data['target_aws_account']
    # we don't need to check explicitly about to check if a snapshot is already retained aws won't throw error even we share to same account
    if is_snapshot_exists(snapshot_identifier) and is_snapshot_available(snapshot_identifier):
        try:
            response = rds_client.modify_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot_identifier,
                AttributeName='restore',
                ValuesToRemove=[target_aws_account]
            )
            print("\nSnapshot Retained successfully")
        except Exception as e:
            print("\nError:", e)
    else:
        if not is_snapshot_exists(snapshot_identifier):
            print("\nNo snapshot found with name {0}.".format(snapshot_identifier))
        print("\nUse option --snapshot-list to list all snapshots")

def info_snapshot(snapshot_id):
    snapshot_identifier = snapshot_id
    if is_snapshot_exists(snapshot_identifier):
        try:
            response = rds_client.describe_db_snapshots(
                DBSnapshotIdentifier=snapshot_identifier
            )
            snapshots = response['DBSnapshots']
            if snapshots:
                snapshot_data = [["DB Identifier" ,"Snapshot Identifier", "Snapshot Type", "Status", "Creation Time"]]
                for snapshot in snapshots:
                    check_create_time = snapshot.get('SnapshotCreateTime')
                    if check_create_time:
                        snapshotcreatetime= check_create_time.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        snapshotcreatetime = ""
                    snapshot_data.append([
                        snapshot['DBInstanceIdentifier'],
                        snapshot['DBSnapshotIdentifier'],
                        snapshot['SnapshotType'],
                        snapshot['Status'],
                        snapshotcreatetime
                    ])
                print("\nSnapshot Info:")
                print(tabulate(snapshot_data, headers="firstrow", tablefmt="grid"))
        except Exception as e:
            print("Error:", e)
    else:
        print("\nNo snapshot info founded for {0}".format(snapshot_identifier))

def list_snapshots():
    db_instance_identifier = global_data['db_instance_identifier']
    if is_dbinstance_exists(db_instance_identifier):
        try:
            response = rds_client.describe_db_snapshots(
                DBInstanceIdentifier=db_instance_identifier,
                SnapshotType='manual'
            )
            snapshots = response['DBSnapshots']
            if snapshots:
                snapshot_data = [["Snapshot Identifier", "Snapshot Type", "Status", "Creation Time"]]
                for snapshot in snapshots:
                    check_create_time = snapshot.get('SnapshotCreateTime')
                    if check_create_time:
                        snapshotcreatetime= check_create_time.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        snapshotcreatetime = ""
                    snapshot_data.append([
                        snapshot['DBSnapshotIdentifier'],
                        snapshot['SnapshotType'],
                        snapshot['Status'],
                        snapshotcreatetime
                    ])
                print("\nList of Snapshots for {0}:".format(db_instance_identifier))
                print(tabulate(snapshot_data, headers="firstrow", tablefmt="grid"))
            else:
                print("No snapshots found")
        except Exception as e:
            print("Error:", e)

def list_shared_snapshots():
    shared_accounts = ['None']
    try:
        response = rds_client.describe_db_snapshots(SnapshotType='manual')
        snapshots = response['DBSnapshots']
        if snapshots:
            snapshot_data = [["DB Identifier" ,"Snapshot Identifier", "Shared To" ]]
            for snapshot in snapshots:
                try:
                    snapshot_atts = rds_client.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'])
                    shared_accounts = [
                        attr['AttributeValues'][0] for attr in snapshot_atts['DBSnapshotAttributesResult']['DBSnapshotAttributes']
                        if attr['AttributeName'] == 'restore']
                    snapshot_data.append([
                        snapshot['DBInstanceIdentifier'],
                        snapshot['DBSnapshotIdentifier'],
                        ','.join(shared_accounts)
                    ])
                except Exception as e:
                    pass # don't need to report error because there may be chances no snapshot is shared at the moment
            
            print("\nAll shared snapshots:")
            print(tabulate(snapshot_data, headers="firstrow", tablefmt="grid"))
        else:
            print("\nNo shared snapshots found")
    
    except Exception as e:
            print("\nError:", e)

def delete_snapshot_all():
    db_instance_identifier = global_data['db_instance_identifier']
    if is_dbinstance_exists(db_instance_identifier):
        try:
            response = rds_client.describe_db_snapshots(
                DBInstanceIdentifier=db_instance_identifier,
                SnapshotType='manual'
            )
            snapshots = response['DBSnapshots']
            if snapshots:
                snapshot_data = [["Snapshot Identifier"]]
                for snapshot in snapshots:
                    response = rds_client.delete_db_snapshot(
                            DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'])
                    snapshot_data.append([
                        snapshot['DBSnapshotIdentifier']
                    ])
                print("\nList of Snapshots belongs to {0} has been deleted".format(db_instance_identifier))
                print(tabulate(snapshot_data, headers="firstrow", tablefmt="grid"))
            else:
                print("No snapshots found")
        except Exception as e:
            print("Error:", e)

def main():
    parser = argparse.ArgumentParser(description='RDS Snapshot Controller')

    parser.add_argument('--db-source', type=str, required=True, help='Source Database prod, test or dev')

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('--snapshot-create', nargs='?', const='no_arg', help='Create a new snapshot')
    group.add_argument('--snapshot-delete', type=str, nargs='?', help='Delete an existing snapshot')
    group.add_argument('--snapshot-copy', type=str, nargs='?', help='Copy a snapshot to locally')
    group.add_argument('--snapshot-share', type=str, nargs='?', help='Share a snapshot with another account')
    group.add_argument('--snapshot-retain', type=str, nargs='?', help='Retain a shared snapshot')
    group.add_argument('--snapshot-info', type=str, nargs='?', help='Info about a snapshot')
    group.add_argument('--snapshot-list',action='store_true', help='List of snapshots belongs to a DB Instance')
    group.add_argument('--snapshot-list-shared',action='store_true', help='List all shared snapshots')
    group.add_argument('--snapshot-delete-all', action='store_true', help='Delete all snapshots belongs to a DB Instance')

    args = parser.parse_args()
    
    db_source(args.db_source)

    if args.snapshot_create:
        if args.snapshot_create == 'no_arg':
            create_snapshot()
        else:
            create_snapshot(args.snapshot_create)
    elif args.snapshot_delete:
        delete_snapshot(args.snapshot_delete)
    elif args.snapshot_copy:
        copy_snapshot(args.snapshot_copy)
    elif args.snapshot_share:
        share_snapshot(args.snapshot_share)
    elif args.snapshot_retain:
        retain_snapshot(args.snapshot_retain)
    elif args.snapshot_info:
        info_snapshot(args.snapshot_info)
    elif args.snapshot_list:
        list_snapshots()
    elif args.snapshot_list_shared:
        list_shared_snapshots()
    elif args.snapshot_delete_all:
        delete_snapshot_all()

if __name__ == "__main__":
    main()