// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef XENGINE_STRUCTURE_TREE_H
#define XENGINE_STRUCTURE_TREE_H

#include <map>
#include <memory>
#include <set>
#include <stack>

namespace xengine
{

template <typename K, typename D>
class CTreeNode
{
public:
    typedef std::shared_ptr<CTreeNode> NodePtr;

    K key;
    D data;
    NodePtr spParent;
    std::set<NodePtr> setChildren;

    CTreeNode()
    {
    }

    CTreeNode(const K& keyIn)
      : key(keyIn)
    {
    }

    CTreeNode(const K& keyIn, const D& dataIn)
      : key(keyIn), data(dataIn)
    {
    }
};

template <typename K, typename D>
class CMultiwayTree
{
public:
    typedef std::shared_ptr<CMultiwayTree> TreePtr;
    typedef typename CTreeNode<K, D>::NodePtr NodePtr;

    NodePtr spRoot;

    CMultiwayTree(NodePtr spRootIn = nullptr)
      : spRoot(spRootIn)
    {
    }

    // postorder traversal
    // walker: bool (*function)(std::shared_ptr<CTreeNode<K, D>>)
    template <typename NodeWalker>
    bool PostorderTraversal(NodeWalker walker)
    {
        NodePtr spNode = spRoot;

        // postorder traversal
        std::stack<NodePtr> st;
        do
        {
            // if spNode != nullptr push and down, or pop and up.
            if (spNode != nullptr)
            {
                if (!spNode->setChildren.empty())
                {
                    st.push(spNode);
                    spNode = *spNode->setChildren.begin();
                    continue;
                }
            }
            else
            {
                spNode = st.top();
                st.pop();
            }

            // call walker
            if (!walker(spNode))
            {
                return false;
            }

            // root or the last child of parent. fetch from stack when next loop
            if (!spNode->spParent || spNode == *spNode->spParent->setChildren.rbegin())
            {
                spNode = nullptr;
            }
            else
            {
                auto it = spNode->spParent->setChildren.find(spNode);
                if (it == spNode->spParent->setChildren.end())
                {
                    return false;
                }
                else
                {
                    spNode = *++it;
                }
            }
        } while (!st.empty());

        return true;
    }
};

template <typename K, typename D>
class CForest
{
public:
    typedef CTreeNode<K, D> Node;
    typedef typename Node::NodePtr NodePtr;
    typedef CMultiwayTree<K, D> Tree;
    typedef typename Tree::TreePtr TreePtr;

    std::map<K, NodePtr> mapNode;
    std::map<K, TreePtr> mapRoot;

    CForest() {}
    ~CForest() {}

    void Clear()
    {
        mapNode.clear();
        mapRoot.clear();
    }

    // postorder traversal
    // walker: bool (*function)(std::shared_ptr<CTreeNode<D>>)
    template <typename NodeWalker>
    bool PostorderTraversal(NodeWalker walker)
    {
        for (auto& r : mapRoot)
        {
            if (!r.second->PostorderTraversal(walker))
            {
                return false;
            }
        }
        return true;
    }

    bool CheckInsert(const K& key, const K& parent, K& root, const std::set<K>& setInvalid = std::set<K>())
    {
        if (key == parent)
        {
            return false;
        }

        NodePtr spNode = GetRelation(key);
        NodePtr sp = GetRelation(parent);
        root = parent;
        if (spNode)
        {
            // already have parent
            if (spNode->spParent)
            {
                return false;
            }

            // cyclic graph
            for (; sp; sp = sp->spParent)
            {
                if (sp->key == key)
                {
                    return false;
                }

                if (!sp->spParent || (!setInvalid.empty() && (setInvalid.find(sp->key) != setInvalid.end())))
                {
                    root = sp->key;
                    break;
                }
            }
        }
        else
        {
            // get parent root
            for (; sp; sp = sp->spParent)
            {
                if (!sp->spParent || (!setInvalid.empty() && (setInvalid.find(sp->key) != setInvalid.end())))
                {
                    root = sp->key;
                    break;
                }
            }
        }

        return true;
    }

    bool Insert(const K& key, const K& parent, const D& data, bool fCheck = true)
    {
        if (fCheck)
        {
            K root;
            if (!CheckInsert(key, parent, root))
            {
                return false;
            }
        }

        // parent
        auto im = mapNode.find(parent);
        if (im == mapNode.end())
        {
            im = mapNode.insert(make_pair(parent, NodePtr(new CTreeNode<K, D>(parent)))).first;
            mapRoot.insert(make_pair(parent, TreePtr(new Tree(im->second))));
        }

        // self
        auto it = mapNode.find(key);
        if (it == mapNode.end())
        {
            it = mapNode.insert(make_pair(key, NodePtr(new CTreeNode<K, D>(key, data)))).first;
        }
        else
        {
            it->second->data = data;
            mapRoot.erase(key);
        }

        it->second->spParent = im->second;
        im->second->setChildren.insert(it->second);

        return true;
    }

    NodePtr RemoveRelation(const K& key)
    {
        auto it = mapNode.find(key);
        if (it == mapNode.end())
        {
            return nullptr;
        }

        NodePtr spNode = it->second;
        NodePtr spParent = spNode->spParent;
        if (spParent)
        {
            spParent->setChildren.erase(spNode);
            // parent is root and no children
            if (spParent->setChildren.empty() && !spParent->spParent)
            {
                mapRoot.erase(spParent->key);
                mapNode.erase(spParent->key);
            }

            spNode->spParent = nullptr;
            if (!spNode->setChildren.empty())
            {
                mapRoot.insert(make_pair(key, TreePtr(new Tree(spNode))));
            }
            else
            {
                mapNode.erase(it);
            }
            return spNode;
        }

        return nullptr;
    }

    NodePtr GetRelation(const K& key)
    {
        auto it = mapNode.find(key);
        return (it == mapNode.end()) ? nullptr : it->second;
    }

    template <typename F>
    CForest<K, F> Copy()
    {
        typedef typename CTreeNode<K, F>::NodePtr NewNodePtr;
        typedef typename CMultiwayTree<K, F>::TreePtr NewTreePtr;

        CForest<K, F> f;
        PostorderTraversal([&](NodePtr spNode) {
            NewNodePtr spNewNode = NewNodePtr(new CTreeNode<K, F>());
            spNewNode->data = spNode->data;
            spNewNode->key = spNode->key;
            f.mapNode.insert(std::make_pair(spNewNode->key, spNewNode));

            // root
            if (!spNode->spParent)
            {
                NewTreePtr spTreePtr = NewTreePtr(new CMultiwayTree<K, F>(spNewNode));
                f.mapRoot.insert(make_pair(spNewNode->key, spTreePtr));
            }

            // children
            for (auto spChild : spNode->setChildren)
            {
                auto it = f.mapNode.find(spChild->key);
                if (it == f.mapNode.end())
                {
                    return false;
                }
                spNewNode->setChildren.insert(it->second);
                it->second->spParent = spNewNode;
            }
            return true;
        });
        return f;
    }

}; // namespace xengine

} // namespace xengine

#endif // XENGINE_STRUCTURE_TREE_H