#include "zeek/Func.h"
#include "zeek/RE.h"
#include "zeek/Val.h"
#include "zeek/Expr.h"
#include "zeek/OpaqueVal.h"
#include "zeek/ZeekString.h"

namespace zeek {

using BoolValPtr = IntrusivePtr<zeek::BoolVal>;
using CountValPtr = IntrusivePtr<zeek::CountVal>;
using DoubleValPtr = IntrusivePtr<zeek::DoubleVal>;
using StringValPtr = IntrusivePtr<zeek::StringVal>;
using IntervalValPtr = IntrusivePtr<zeek::IntervalVal>;
using PatternValPtr = IntrusivePtr<zeek::PatternVal>;
using FuncValPtr = IntrusivePtr<zeek::FuncVal>;
using SubNetValPtr = IntrusivePtr<zeek::SubNetVal>;

namespace detail {

extern TypePtr types__CPP[];

// Helper functions.

StringValPtr str_concat__CPP(const String* s1, const String* s2)
	{
	std::vector<const String*> strings(2);
	strings.push_back(s1);
	strings.push_back(s2);

	return make_intrusive<StringVal>(concatenate(strings));
	}

ListValPtr index_val__CPP(std::vector<ValPtr> indices)
	{
	auto ind_v = make_intrusive<ListVal>(TYPE_ANY);

	// In the future, we could provide N versions of this that
	// unroll the loop.
	for ( auto i : indices )
		ind_v->Append(i);

	return ind_v;
	}

ValPtr index_table__CPP(TableValPtr t, std::vector<ValPtr> indices)
	{
	return t->FindOrDefault(index_val__CPP(std::move(indices)));
	}

// Call out to the given script or BiF function.
inline ValPtr invoke__CPP(Func* f, std::vector<ValPtr> args)
	{
	return f->Invoke(&args, nullptr);
	}

// Convert a bare Val* to its corresponding IntrusivePtr.
template <typename T>
IntrusivePtr<T> val_to_valptr__CPP(T* v) { return {NewRef{}, v}; }

// Execute an assignment "v1[v2] = v3".
void assign_to_index__CPP(ValPtr v1, ValPtr v2, ValPtr v3)
	{
	bool iterators_invalidated;
	auto err_msg = zeek::detail::assign_to_index(v1, v2, v3,
							iterators_invalidated);
	if ( err_msg )
		reporter->Error("%s", err_msg);
	}

TableValPtr table_coerce__CPP(const ValPtr& v, const TypePtr& t)
	{
	TableVal* tv = v->AsTableVal();

	if ( tv->Size() > 0 )
		reporter->Error("coercion of non-empty table/set");

	return make_intrusive<TableVal>(cast_intrusive<TableType>(t),
					tv->GetAttrs());
	}

TableValPtr set_constructor__CPP(std::vector<ValPtr> elements, TableTypePtr t,
					AttributesPtr attrs)
	{
	auto aggr = make_intrusive<TableVal>(t, attrs);

	for ( const auto& elem : elements )
		aggr->Assign(std::move(elem), nullptr);

	return aggr;
	}

TableValPtr table_constructor__CPP(std::vector<ValPtr> indices,
					std::vector<ValPtr> vals,
					TableTypePtr t, AttributesPtr attrs)
	{
	const auto& yt = t->Yield().get();
	auto n = indices.size();

	auto aggr = make_intrusive<TableVal>(t, attrs);

	for ( auto i = 0; i < n; ++i )
		{
		auto v = check_and_promote(vals[i], yt, true);
		if ( v )
			aggr->Assign(std::move(indices[i]), std::move(v));
		}

	return aggr;
	}

RecordValPtr record_constructor();
VectorValPtr vector_constructor();
void schedule();