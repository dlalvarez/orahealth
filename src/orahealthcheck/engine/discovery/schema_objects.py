"""Descubrimiento y construcción de evidencia del grupo schema_objects.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

import logging
from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin
from orahealthcheck.engine.discovery.constants import ORACLE_INTERNAL_SCHEMAS


class SchemaObjectsMixin(CommonMixin):
    def _discover_schema_objects_inventory(self, connector: Any) -> dict[str, Any]:
        schema_objects: dict[str, Any] = {}
        schema_objects["invalid_objects_detail"] = self._query_schema_rows(connector, "objetos inválidos no mantenidos por Oracle", """
            select o.owner, o.object_name, o.object_type, o.status, o.created, o.last_ddl_time,
                   u.oracle_maintained
            from dba_objects o
            left join dba_users u on u.username = o.owner
            where o.status <> 'VALID'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by o.owner, o.object_type, o.object_name
        """, """
            select o.owner, o.object_name, o.object_type, o.status, o.created, o.last_ddl_time,
                   null as oracle_maintained
            from dba_objects o
            where o.status <> 'VALID'
              and o.owner not in ({internal_schemas})
            order by o.owner, o.object_type, o.object_name
        """)
        schema_objects["unusable_indexes"] = self._query_schema_rows(connector, "índices no utilizables", """
            select i.owner, i.index_name, i.table_owner, i.table_name, i.status, i.partitioned,
                   i.index_type, i.tablespace_name, u.oracle_maintained
            from dba_indexes i
            left join dba_users u on u.username = i.owner
            where i.status = 'UNUSABLE'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by i.owner, i.index_name
        """, """
            select i.owner, i.index_name, i.table_owner, i.table_name, i.status, i.partitioned,
                   i.index_type, i.tablespace_name, null as oracle_maintained
            from dba_indexes i
            where i.status = 'UNUSABLE'
              and i.owner not in ({internal_schemas})
            order by i.owner, i.index_name
        """)
        schema_objects["unusable_index_partitions"] = self._query_schema_rows(connector, "particiones de índices no utilizables", """
            select i.owner, i.index_name, p.partition_name, cast(null as varchar2(128)) as subpartition_name,
                   i.table_owner, i.table_name, p.status, 'PARTITION' as "level", u.oracle_maintained
            from dba_ind_partitions p
            join dba_indexes i on i.owner = p.index_owner and i.index_name = p.index_name
            left join dba_users u on u.username = i.owner
            where p.status = 'UNUSABLE'
              and nvl(u.oracle_maintained, 'N') = 'N'
            union all
            select i.owner, i.index_name, sp.partition_name, sp.subpartition_name,
                   i.table_owner, i.table_name, sp.status, 'SUBPARTITION' as "level", u.oracle_maintained
            from dba_ind_subpartitions sp
            join dba_indexes i on i.owner = sp.index_owner and i.index_name = sp.index_name
            left join dba_users u on u.username = i.owner
            where sp.status = 'UNUSABLE'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by owner, index_name, "level", partition_name, subpartition_name
        """, """
            select i.owner, i.index_name, p.partition_name, cast(null as varchar2(128)) as subpartition_name,
                   i.table_owner, i.table_name, p.status, 'PARTITION' as "level", null as oracle_maintained
            from dba_ind_partitions p
            join dba_indexes i on i.owner = p.index_owner and i.index_name = p.index_name
            where p.status = 'UNUSABLE'
              and i.owner not in ({internal_schemas})
            union all
            select i.owner, i.index_name, sp.partition_name, sp.subpartition_name,
                   i.table_owner, i.table_name, sp.status, 'SUBPARTITION' as "level", null as oracle_maintained
            from dba_ind_subpartitions sp
            join dba_indexes i on i.owner = sp.index_owner and i.index_name = sp.index_name
            where sp.status = 'UNUSABLE'
              and i.owner not in ({internal_schemas})
            order by owner, index_name, "level", partition_name, subpartition_name
        """)
        schema_objects["disabled_constraints"] = self._query_schema_rows(connector, "constraints deshabilitadas", """
            select c.owner, c.constraint_name, c.constraint_type, c.table_name, c.status, c.validated,
                   c.deferrable, c.deferred, c.generated,
                   case when c.constraint_type = 'C' then substr(c.search_condition_vc, 1, 1000) else null end as search_condition,
                   u.oracle_maintained
            from dba_constraints c
            left join dba_users u on u.username = c.owner
            where c.status = 'DISABLED'
              and c.constraint_type in ('P','R','U','C')
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by c.owner, c.table_name, c.constraint_name
        """, """
            select c.owner, c.constraint_name, c.constraint_type, c.table_name, c.status, c.validated,
                   c.deferrable, c.deferred, c.generated,
                   case when c.constraint_type = 'C' then substr(c.search_condition_vc, 1, 1000) else null end as search_condition,
                   null as oracle_maintained
            from dba_constraints c
            where c.status = 'DISABLED'
              and c.constraint_type in ('P','R','U','C')
              and c.owner not in ({internal_schemas})
            order by c.owner, c.table_name, c.constraint_name
        """)
        schema_objects["disabled_triggers"] = self._query_schema_rows(connector, "triggers deshabilitados", """
            select t.owner, t.trigger_name, t.table_owner, t.table_name, t.trigger_type,
                   t.triggering_event, t.status, u.oracle_maintained
            from dba_triggers t
            left join dba_users u on u.username = t.owner
            where t.status = 'DISABLED'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by t.owner, t.trigger_name
        """, """
            select t.owner, t.trigger_name, t.table_owner, t.table_name, t.trigger_type,
                   t.triggering_event, t.status, null as oracle_maintained
            from dba_triggers t
            where t.status = 'DISABLED'
              and t.owner not in ({internal_schemas})
            order by t.owner, t.trigger_name
        """)
        table_stats_where = "and s.object_type = 'TABLE' and nvl(s.global_stats, 'YES') = 'YES' and nvl(t.temporary, 'N') = 'N'"
        schema_objects["stale_table_statistics"] = self._query_schema_rows(connector, "tablas con estadísticas desactualizadas", f"""
            select s.owner, s.table_name, s.object_type, s.stale_stats, s.last_analyzed, s.num_rows,
                   s.blocks, s.stattype_locked, t.temporary, u.oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            left join dba_users u on u.username = s.owner
            where s.stale_stats = 'YES'
              {table_stats_where}
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by s.owner, s.table_name
        """, f"""
            select s.owner, s.table_name, s.object_type, s.stale_stats, s.last_analyzed, s.num_rows,
                   s.blocks, s.stattype_locked, t.temporary, null as oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            where s.stale_stats = 'YES'
              {table_stats_where}
              and s.owner not in ({{internal_schemas}})
            order by s.owner, s.table_name
        """)
        schema_objects["missing_table_statistics"] = self._query_schema_rows(connector, "tablas sin estadísticas", f"""
            select s.owner, s.table_name, s.object_type, s.stale_stats, s.last_analyzed, s.num_rows,
                   s.blocks, t.temporary, u.oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            left join dba_users u on u.username = s.owner
            where s.last_analyzed is null
              {table_stats_where}
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by s.owner, s.table_name
        """, f"""
            select s.owner, s.table_name, s.object_type, s.stale_stats, s.last_analyzed, s.num_rows,
                   s.blocks, t.temporary, null as oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            where s.last_analyzed is null
              {table_stats_where}
              and s.owner not in ({{internal_schemas}})
            order by s.owner, s.table_name
        """)
        schema_objects["locked_table_statistics"] = self._query_schema_rows(connector, "tablas con estadísticas bloqueadas", f"""
            select s.owner, s.table_name, s.object_type, s.stattype_locked, s.last_analyzed,
                   s.stale_stats, s.num_rows, t.temporary, u.oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            left join dba_users u on u.username = s.owner
            where s.stattype_locked is not null
              {table_stats_where}
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by s.owner, s.table_name
        """, f"""
            select s.owner, s.table_name, s.object_type, s.stattype_locked, s.last_analyzed,
                   s.stale_stats, s.num_rows, t.temporary, null as oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            where s.stattype_locked is not null
              {table_stats_where}
              and s.owner not in ({{internal_schemas}})
            order by s.owner, s.table_name
        """)
        recyclebin_rows = self._query_schema_rows(connector, "objetos en recyclebin", """
            select r.owner, r.object_name, r.original_name, r.type, r.ts_name, r.createtime,
                   r.droptime, r.can_undrop, r.can_purge,
                   round(nvl(s.bytes, r.space * ts.block_size) / 1024 / 1024, 2) as space_mb,
                   u.oracle_maintained
            from dba_recyclebin r
            left join dba_users u on u.username = r.owner
            left join dba_segments s on s.owner = r.owner and s.segment_name = r.object_name
            left join dba_tablespaces ts on ts.tablespace_name = r.ts_name
            where nvl(u.oracle_maintained, 'N') = 'N'
            order by r.owner, r.droptime desc, r.object_name
        """, """
            select r.owner, r.object_name, r.original_name, r.type, r.ts_name, r.createtime,
                   r.droptime, r.can_undrop, r.can_purge,
                   round(nvl(s.bytes, r.space * ts.block_size) / 1024 / 1024, 2) as space_mb,
                   null as oracle_maintained
            from dba_recyclebin r
            left join dba_segments s on s.owner = r.owner and s.segment_name = r.object_name
            left join dba_tablespaces ts on ts.tablespace_name = r.ts_name
            where r.owner not in ({internal_schemas})
            order by r.owner, r.droptime desc, r.object_name
        """)
        schema_objects["recyclebin_objects"] = recyclebin_rows
        schema_objects["recyclebin_total_mb"] = round(sum(float(row.get("space_mb") or 0) for row in recyclebin_rows), 2)

        schema_objects["tables_without_primary_key"] = self._query_schema_rows(connector, "tablas de aplicación sin llave primaria", """
            select t.owner, t.table_name, t.tablespace_name, t.temporary, t.nested, t.dropped, u.oracle_maintained
            from dba_tables t
            left join dba_users u on u.username = t.owner
            where nvl(u.oracle_maintained, 'N') = 'N'
              and nvl(t.temporary, 'N') = 'N'
              and nvl(t.nested, 'NO') = 'NO'
              and nvl(t.dropped, 'NO') = 'NO'
              and not exists (
                select 1 from dba_constraints c
                where c.owner = t.owner and c.table_name = t.table_name and c.constraint_type = 'P'
              )
            order by t.owner, t.table_name
        """, """
            select t.owner, t.table_name, t.tablespace_name, t.temporary, t.nested, t.dropped, null as oracle_maintained
            from dba_tables t
            where t.owner not in ({internal_schemas})
              and nvl(t.temporary, 'N') = 'N'
              and nvl(t.nested, 'NO') = 'NO'
              and nvl(t.dropped, 'NO') = 'NO'
              and not exists (
                select 1 from dba_constraints c
                where c.owner = t.owner and c.table_name = t.table_name and c.constraint_type = 'P'
              )
            order by t.owner, t.table_name
        """)
        schema_objects["foreign_keys_without_index"] = self._query_schema_rows(connector, "llaves foráneas sin índice compatible", """
            with fk_cols as (
              select owner, constraint_name, table_name,
                     listagg(column_name, ',') within group (order by position) as fk_columns,
                     count(*) as column_count
              from dba_cons_columns
              group by owner, constraint_name, table_name
            ), idx_cols as (
              select index_owner, index_name, table_owner, table_name,
                     listagg(column_name, ',') within group (order by column_position) as leading_columns
              from dba_ind_columns
              group by index_owner, index_name, table_owner, table_name
            )
            select c.owner, c.constraint_name, c.table_name, fc.fk_columns, fc.column_count, c.status, c.validated, u.oracle_maintained
            from dba_constraints c
            join fk_cols fc on fc.owner = c.owner and fc.constraint_name = c.constraint_name
            join dba_tables t on t.owner = c.owner and t.table_name = c.table_name
            left join dba_users u on u.username = c.owner
            where c.constraint_type = 'R'
              and c.status = 'ENABLED'
              and nvl(u.oracle_maintained, 'N') = 'N'
              and nvl(t.temporary, 'N') = 'N'
              and not exists (
                select 1 from idx_cols i
                where i.table_owner = c.owner and i.table_name = c.table_name
                  and substr(i.leading_columns || ',', 1, length(fc.fk_columns || ',')) = fc.fk_columns || ','
              )
            order by c.owner, c.table_name, c.constraint_name
        """, """
            with fk_cols as (
              select owner, constraint_name, table_name, listagg(column_name, ',') within group (order by position) as fk_columns, count(*) as column_count from dba_cons_columns group by owner, constraint_name, table_name
            ), idx_cols as (
              select index_owner, index_name, table_owner, table_name, listagg(column_name, ',') within group (order by column_position) as leading_columns from dba_ind_columns group by index_owner, index_name, table_owner, table_name
            )
            select c.owner, c.constraint_name, c.table_name, fc.fk_columns, fc.column_count, c.status, c.validated, null as oracle_maintained
            from dba_constraints c join fk_cols fc on fc.owner = c.owner and fc.constraint_name = c.constraint_name join dba_tables t on t.owner = c.owner and t.table_name = c.table_name
            where c.constraint_type = 'R' and c.status = 'ENABLED' and c.owner not in ({internal_schemas}) and nvl(t.temporary, 'N') = 'N'
              and not exists (select 1 from idx_cols i where i.table_owner = c.owner and i.table_name = c.table_name and substr(i.leading_columns || ',', 1, length(fc.fk_columns || ',')) = fc.fk_columns || ',')
            order by c.owner, c.table_name, c.constraint_name
        """)
        schema_objects["tables_with_long_columns"] = self._query_schema_rows(connector, "columnas LONG o LONG RAW en tablas de aplicación", """
            select c.owner, c.table_name, c.column_name, c.data_type, u.oracle_maintained
            from dba_tab_columns c
            join dba_tables t on t.owner = c.owner and t.table_name = c.table_name
            left join dba_users u on u.username = c.owner
            where c.data_type in ('LONG', 'LONG RAW')
              and nvl(u.oracle_maintained, 'N') = 'N'
              and nvl(t.temporary, 'N') = 'N'
            order by c.owner, c.table_name, c.column_id
        """, """
            select c.owner, c.table_name, c.column_name, c.data_type, null as oracle_maintained
            from dba_tab_columns c join dba_tables t on t.owner = c.owner and t.table_name = c.table_name
            where c.data_type in ('LONG', 'LONG RAW') and c.owner not in ({internal_schemas}) and nvl(t.temporary, 'N') = 'N'
            order by c.owner, c.table_name, c.column_id
        """)
        schema_objects["indexes_too_many_columns"] = self._query_schema_rows(connector, "índices con demasiadas columnas", """
            select i.owner, i.index_name, i.table_owner, i.table_name, count(c.column_name) as column_count, i.index_type, i.status, u.oracle_maintained
            from dba_indexes i
            join dba_ind_columns c on c.index_owner = i.owner and c.index_name = i.index_name
            left join dba_users u on u.username = i.owner
            where nvl(u.oracle_maintained, 'N') = 'N'
            group by i.owner, i.index_name, i.table_owner, i.table_name, i.index_type, i.status, u.oracle_maintained
            order by column_count desc, i.owner, i.index_name
        """, """
            select i.owner, i.index_name, i.table_owner, i.table_name, count(c.column_name) as column_count, i.index_type, i.status, null as oracle_maintained
            from dba_indexes i join dba_ind_columns c on c.index_owner = i.owner and c.index_name = i.index_name
            where i.owner not in ({internal_schemas})
            group by i.owner, i.index_name, i.table_owner, i.table_name, i.index_type, i.status
            order by column_count desc, i.owner, i.index_name
        """)
        schema_objects["invalid_synonyms"] = self._query_schema_rows(connector, "sinónimos locales con destino inexistente", """
            select s.owner, s.synonym_name, s.table_owner, s.table_name, s.db_link,
                   u.oracle_maintained,
                   tu.oracle_maintained as table_owner_oracle_maintained
            from dba_synonyms s
            left join dba_users u on u.username = s.owner
            left join dba_users tu on tu.username = s.table_owner
            left join dba_objects o on o.owner = s.table_owner and o.object_name = s.table_name
            where s.db_link is null
              and o.object_name is null
              and s.owner <> 'PUBLIC'
              and nvl(u.oracle_maintained, 'N') = 'N'
              and nvl(tu.oracle_maintained, 'N') = 'N'
            order by s.owner, s.synonym_name
        """, """
            select s.owner, s.synonym_name, s.table_owner, s.table_name, s.db_link,
                   null as oracle_maintained,
                   null as table_owner_oracle_maintained
            from dba_synonyms s
            left join dba_objects o on o.owner = s.table_owner and o.object_name = s.table_name
            where s.db_link is null
              and o.object_name is null
              and s.owner <> 'PUBLIC'
              and s.owner not in ({internal_schemas})
              and s.table_owner not in ({internal_schemas})
            order by s.owner, s.synonym_name
        """)
        return {"schema_objects": schema_objects}

    def _query_schema_rows(self, connector: Any, label: str, sql: str, fallback_sql: str | None = None) -> list[dict[str, Any]]:
        rows, error = self._query_rows_with_error(connector, label, sql, log_warning=False)
        if error and not fallback_sql:
            logging.warning("Oracle inventory query failed for %s: %s", label, error)
            self._record_query_failure(label, error)
        if error and fallback_sql:
            logging.info("Retrying Oracle schema object query without ORACLE_MAINTAINED for %s", label)
            rows = self._query_rows(connector, f"{label} sin columna oracle_maintained", fallback_sql.format(internal_schemas=self._sql_in_list(ORACLE_INTERNAL_SCHEMAS)))
        return rows

    def _build_schema_objects_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        schema_objects = database.get("schema_objects") if isinstance(database.get("schema_objects"), dict) else {}
        field = check.collector.get("field", check.check_id)
        rows = schema_objects.get(field, [])
        if rows is None:
            rows = []
        original_rows = rows if isinstance(rows, list) else [rows]
        filtered_rows = self._filter_oracle_maintained_schema_rows(original_rows)
        if check.check_id == "indexes_too_many_columns":
            max_columns = int(check.evaluator.get("warning", check.evaluator.get("max_columns", 8)) or 8)
            filtered_rows = [row for row in filtered_rows if isinstance(row, dict) and int(row.get("column_count") or 0) > max_columns]
        evidence = {
            "metric": check.check_id,
            "label": check.collector.get("label", check.title),
            "source": check.collector.get("source_view", "inventario de esquemas y objetos Oracle"),
            "affected_count": len(filtered_rows),
            "rows": filtered_rows,
        }
        if check.check_id == "indexes_too_many_columns":
            evidence["max_columns"] = int(check.evaluator.get("warning", check.evaluator.get("max_columns", 8)) or 8)
        if check.check_id == "recyclebin_objects":
            evidence["total_mb"] = round(sum(float(row.get("space_mb") or 0) for row in filtered_rows if isinstance(row, dict)), 2)
        if filtered_rows != original_rows:
            evidence["inventory_count"] = len(original_rows)
            evidence["excluded_count"] = len(original_rows) - len(filtered_rows)
            evidence["classification_note"] = "Se excluyeron objetos de usuarios mantenidos por Oracle del hallazgo principal."
        if field not in schema_objects and check.collector.get("missing_status"):
            evidence["collection_error"] = f"No se encontró la sección {field} en el inventario de esquemas y objetos"
        return evidence

    def _filter_oracle_maintained_schema_rows(self, rows: list[Any]) -> list[Any]:
        filtered = []
        for row in rows:
            if not isinstance(row, dict):
                filtered.append(row)
                continue
            oracle_maintained = str(row.get("oracle_maintained", "")).upper() == "Y"
            owner = str(row.get("owner", row.get("username", row.get("table_owner", "")))).upper()
            table_owner = str(row.get("table_owner", "")).upper()
            table_owner_oracle_maintained = str(row.get("table_owner_oracle_maintained", "")).upper() == "Y"
            if not owner or oracle_maintained or owner in ORACLE_INTERNAL_SCHEMAS:
                continue
            if row.get("synonym_name") and (owner == "PUBLIC" or table_owner in ORACLE_INTERNAL_SCHEMAS or table_owner_oracle_maintained):
                continue
            filtered.append(row)
        return filtered
