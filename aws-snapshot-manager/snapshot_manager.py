"""
This script provides functionality to manage RDS snapshots using boto3 client.
"""
from datetime import datetime
import warnings
import argparse
import sys
import traceback
import logging
import boto3
import yaml
from tabulate import tabulate
from botocore.exceptions import ClientError

warnings.filterwarnings('ignore')
rds_client = boto3.client('rds' ,verify=False)

# define global variables
global_data = {}

#functions
def read_yaml():
    """function to read custom and default config files"""
    with open('default_config.yaml', 'r', encoding="utf-8") as file:
        defaults = yaml.safe_load(file)
    with open('custom_config.yaml', 'r', encoding="utf-8") as file:
        config = yaml.safe_load(file)
    return defaults, config


def is_config_empty(data):
    """function to check to find any empty configuration"""
    empty_config = []
    for key, value in data.items():
        if value is None or value == "":
            empty_config.append(key)
    if empty_config:
        print("\nPlease update yaml configuration:")
        return True
    return False

def db_source(db_name):
    """function to map configuration based on --db-source option"""
    defaults, config = read_yaml()
    if db_name == 'prod':
        global_data['db_instance_identifier'] = config['rds_prod_db_instance_identifier']
    elif db_name == 'test':
        global_data['db_instance_identifier'] = config['rds_test_db_instance_identifier']
    elif db_name == 'dev':
        global_data['db_instance_identifier'] = config['rds_dev_db_instance_identifier']
    else:
        print("\n Database source can be prod, test or dev")
        sys.exit()
    if db_name in ['prod','test','dev']:
        global_data['snapshot_identifier'] = global_data['db_instance_identifier']+ \
        "-snapshot"+datetime.now().strftime("-%Y%m%d-%H%M%S")
        # for snapshot copy
        global_data['copy_suffix']= defaults['default_snapshot_copy_identifier_suffix']
        global_data['copy_region']= defaults['default_copy_region']
        global_data['kms_key']= defaults['default_snapshot_kms_key_arn']
        # for snapshot share
        global_data['target_aws_account']= defaults['default_test_account_id']

    if not is_config_empty(global_data):
        return True
    return False


def is_snapshot_exists(snapshot_id):
    """function to check a snapshot exist with same name"""
    try:
        rds_client.describe_db_snapshots(
            DBSnapshotIdentifier=snapshot_id
        )
        return True
    except rds_client.exceptions.DBSnapshotNotFoundFault:
        return False
    except ClientError:
        logging.error(traceback.format_exc())
        sys.exit()

def is_dbinstance_exists(db_identifier):
    """function to check a db instance exist"""
    try:
        rds_client.describe_db_instances(DBInstanceIdentifier=db_identifier)
        return True
    except rds_client.exceptions.DBInstanceNotFoundFault:
        return False
    except ClientError:
        logging.error(traceback.format_exc())
        sys.exit()

def is_snapshot_available(snapshot_id):
    """function to check a snapshot in available state"""
    if is_snapshot_exists(snapshot_id):
        try:
            response = rds_client.describe_db_snapshots(
                DBSnapshotIdentifier=snapshot_id
            )
            snapshot = response['DBSnapshots']
            if snapshot[0]['Status'] == 'available':
                return True
            print(f"\nSnapshot {snapshot_id} is not in available state")
            return False
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()
    else:
        print(f"\nNo snapshot exists with name {snapshot_id}")
        return False

def is_db_creating_snapshot_currently(db_identifier):
    """function to check a DB instance is currently creating any snapshot"""
    if is_dbinstance_exists(db_identifier):
        try:
            response = rds_client.describe_db_snapshots(
                DBInstanceIdentifier=db_identifier,
                SnapshotType='manual'
            )
            snapshots = response['DBSnapshots']
            for snapshot in snapshots:
                if snapshot['Status'] == 'creating':
                    print(f"\nDBInstance busy creating snapshot {snapshot['DBSnapshotIdentifier']}")
                    return True
            return False
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()
    return False

def create_snapshot(snapshot_id=None):
    """function to create a snapshot"""
    if snapshot_id is None:
        db_instance_identifier = global_data['db_instance_identifier']
        snapshot_identifier = global_data['snapshot_identifier']
    else:
        db_instance_identifier = global_data['db_instance_identifier']
        snapshot_identifier = snapshot_id
    if is_dbinstance_exists(db_instance_identifier) and \
        not is_snapshot_exists(snapshot_identifier) and \
        not is_db_creating_snapshot_currently(db_instance_identifier):
        try:
            rds_client.create_db_snapshot(
                DBSnapshotIdentifier=snapshot_identifier,
                DBInstanceIdentifier=db_instance_identifier
            )
            print(f"\nStarted creating {snapshot_identifier}")
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()
    else:
        if is_snapshot_exists(snapshot_identifier):
            print(f"\nA snapshot with name {snapshot_identifier} already exist.")

def delete_snapshot(snapshot_id):
    """function to delete a snapshot"""
    if is_snapshot_exists(snapshot_id) and is_snapshot_available(snapshot_id):
        try:
            rds_client.delete_db_snapshot(
                DBSnapshotIdentifier=snapshot_id
            )
            print("Snapshot deleted successfully!")
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()
    else:
        print(f"\nNo snapshot found with name {snapshot_id}")

def copy_snapshot(snapshot_id):
    """function to copy a snapshot"""
    source_snapshot_identifier = snapshot_id
    target_snapshot_identifier = source_snapshot_identifier + global_data['copy_suffix']
    if is_snapshot_exists(source_snapshot_identifier) and \
        not is_snapshot_exists(target_snapshot_identifier) and \
        is_snapshot_available(source_snapshot_identifier):
        try:
            rds_client.copy_db_snapshot(
            SourceDBSnapshotIdentifier=source_snapshot_identifier,
            TargetDBSnapshotIdentifier=target_snapshot_identifier,
            KmsKeyId=global_data['kms_key']
            )
            print("\nSnapshot copied successfully")
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()
    else:
        if not is_snapshot_exists(source_snapshot_identifier):
            print(f"\nSource snapshot {source_snapshot_identifier} doesn't found.")
        if is_snapshot_exists(target_snapshot_identifier):
            print(f"\nTarget snapshot {target_snapshot_identifier} already exist.")
        print("\nUse option --snapshot-list to list all snapshots")

def share_snapshot(snapshot_id):
    """function to share a snapshot"""
    target_aws_account = global_data['target_aws_account']
    # we don't need to check explicitly about to check if a snapshot is already shared
    # aws won't throw error even we share to same account
    if is_snapshot_exists(snapshot_id) and is_snapshot_available(snapshot_id):
        try:
            rds_client.modify_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot_id,
                AttributeName='restore',
                ValuesToAdd=[target_aws_account]
            )
            print("\nSnapshot shared successfully")
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()
    else:
        if not is_snapshot_exists(snapshot_id):
            print(f"\nNo snapshot found with name {snapshot_id}.")
        print("\nUse option --snapshot-list to list all snapshots")

def revoke_snapshot(snapshot_id):
    """function to revoke a shared snapshot"""
    target_aws_account = global_data['target_aws_account']
    # we don't need to check explicitly about to check if a snapshot is already retained
    # aws won't throw error even we share to same account
    if is_snapshot_exists(snapshot_id) and is_snapshot_available(snapshot_id):
        try:
            rds_client.modify_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot_id,
                AttributeName='restore',
                ValuesToRemove=[target_aws_account]
            )
            print("\nSnapshot Revoked successfully")
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()
    else:
        if not is_snapshot_exists(snapshot_id):
            print(f"\nNo snapshot found with name {snapshot_id}.")
        print("\nUse option --snapshot-list to list all snapshots")

def info_snapshot(snapshot_id):
    """function to info a snapshot"""
    if is_snapshot_exists(snapshot_id) and is_snapshot_available(snapshot_id):
        try:
            response = rds_client.describe_db_snapshots(
                DBSnapshotIdentifier=snapshot_id
            )
            snapshot_meta_dict = response['DBSnapshots'][0]
            snapshot_data = [["Property","Value"]]
            for each_meta_property in snapshot_meta_dict:
                snapshot_data.append([each_meta_property,snapshot_meta_dict[each_meta_property]])
            print("\nSnapshot Info:")
            print(tabulate(snapshot_data, headers="firstrow", tablefmt="grid"))
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()
    else:
        print(f"\nNo snapshot info founded for {snapshot_id}")

def list_snapshots():
    """function to list all snapshots belong to DB instance"""
    db_instance_identifier = global_data['db_instance_identifier']
    if is_dbinstance_exists(db_instance_identifier):
        try:
            response = rds_client.describe_db_snapshots(
                DBInstanceIdentifier=db_instance_identifier,
                SnapshotType='manual'
            )
            snapshots = response['DBSnapshots']
            if snapshots:
                snapshot_data = [["Snapshot Identifier",
                                  "Snapshot Type",
                                  "Status",
                                  "Creation Time"]]
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
                print(f"\nList of Snapshots belong to {db_instance_identifier}:")
                print(tabulate(snapshot_data, headers="firstrow", tablefmt="grid"))
            else:
                print("No snapshots found")
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()

def list_shared_snapshots():
    """function to list all shared snapshots belong to DB instance"""
    shared_accounts = ['None']
    try:
        response = rds_client.describe_db_snapshots(SnapshotType='manual')
        snapshots = response['DBSnapshots']
        if snapshots:
            snapshot_data = [["DB Identifier" ,"Snapshot Identifier", "Shared To" ]]
            for snapshot in snapshots:
                try:
                    snapshot_atts = rds_client.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'])
                    shared_accounts = [
                        attr['AttributeValues'][0]
                        for attr in snapshot_atts['DBSnapshotAttributesResult']['DBSnapshotAttributes']
                        if attr['AttributeName'] == 'restore']
                    snapshot_data.append([
                        snapshot['DBInstanceIdentifier'],
                        snapshot['DBSnapshotIdentifier'],
                        ','.join(shared_accounts)
                    ])
                except ClientError:
                    pass
                except IndexError:
                    pass
    # don't need to report error because there may be chances no snapshot is shared at the moment
            print("\nAll shared snapshots:")
            print(tabulate(snapshot_data, headers="firstrow", tablefmt="grid"))
        else:
            print("\nNo shared snapshots found")
    except ClientError:
        logging.error(traceback.format_exc())
        sys.exit()

def delete_snapshot_all():
    """function to delete all snapshots belong to DB instance"""
    db_instance_identifier = global_data['db_instance_identifier']
    if is_dbinstance_exists(db_instance_identifier):
        try:
            response = rds_client.describe_db_snapshots(
                DBInstanceIdentifier=db_instance_identifier,
                SnapshotType='manual'
            )
            snapshots = response['DBSnapshots']
            if snapshots:
                snapshot_data = [["Snapshot Identifier","Deleted","Info"]]
                for snapshot in snapshots:
                    if is_snapshot_available(snapshot['DBSnapshotIdentifier']):
                        response = rds_client.delete_db_snapshot(
                                DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'])
                        snapshot_data.append([
                            snapshot['DBSnapshotIdentifier'],
                            "Yes",
                            "-"
                        ])
                    else:
                        snapshot_data.append([
                            snapshot['DBSnapshotIdentifier'],
                            "No",
                            "Not in available state"
                        ])
                print(f"\nAffected snapshots belong to {db_instance_identifier}")
                print(tabulate(snapshot_data, headers="firstrow", tablefmt="grid"))
            else:
                print("No snapshots found")
        except ClientError:
            logging.error(traceback.format_exc())
            sys.exit()

def main():
    """main function to start execution"""
    parser = argparse.ArgumentParser(description='RDS Snapshot Manager')
    parser.add_argument('--db-source',
                        type=str,
                        required=True,
                        help='Source Database prod, test or dev')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--snapshot-create',
                       nargs='?',
                       const='no_arg',
                       help='Create a new snapshot')
    group.add_argument('--snapshot-delete',
                       type=str,
                       nargs='?',
                       help='Delete an existing snapshot')
    group.add_argument('--snapshot-copy',
                       type=str,
                       nargs='?',
                       help='Copy a snapshot locally')
    group.add_argument('--snapshot-share',
                       type=str,
                       nargs='?',
                       help='Share a snapshot with another account')
    group.add_argument('--snapshot-revoke',
                       type=str,
                       nargs='?',
                       help='Revoke a shared snapshot')
    group.add_argument('--snapshot-info',
                       type=str,
                       nargs='?',
                       help='Info about a snapshot')
    group.add_argument('--snapshot-list',
                       action='store_true',
                       help='List of snapshots belongs to a DB Instance')
    group.add_argument('--snapshot-list-shared',
                       action='store_true',
                       help='List all shared snapshots')
    group.add_argument('--snapshot-delete-all',
                       action='store_true',
                       help='Delete all snapshots belongs to a DB Instance')

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
    elif args.snapshot_revoke:
        revoke_snapshot(args.snapshot_revoke)
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
